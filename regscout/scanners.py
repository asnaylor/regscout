"""Remote vulnerability scanners for container registries, OCI SBOMs, OSV.dev, cve.now, and local Trivy fallback."""

from __future__ import annotations

import concurrent.futures
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from regscout import __version__
from regscout.auth import resolve_registry_auth
from regscout.discovery import DiscoveredImage, normalize_ecosystem

USER_AGENT = f"regscout/{__version__}"

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

OSV_ECOSYSTEM_MAP: Dict[str, str] = {
    "pypi": "PyPI",
    "go": "Go",
    "npm": "npm",
    "crates.io": "crates.io",
}


@dataclass
class VulnerabilityFinding:
    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss: Optional[float]
    package: str
    version: str
    fixed_by: Optional[str]
    title: str
    source: str  # e.g. "harbor-trivy", "docker-scout", "quay-clair", "oci-sbom-osv", "trivy-local", "osv.dev", "cve.now"
    aliases: List[str] = field(default_factory=list)


@dataclass
class ImageScanResult:
    image: str
    registry: str
    repository: str
    tag: Optional[str]
    digest: Optional[str]
    scanners_used: List[str] = field(default_factory=list)
    upstream_repo: Optional[str] = None
    auth_source: Optional[str] = None
    scan_triggered: bool = False
    status: str = "ok"  # "ok", "auth_required", "not_found", "unscanned", "error"
    notes: List[str] = field(default_factory=list)
    findings: List[VulnerabilityFinding] = field(default_factory=list)


@dataclass
class PackageScanResult:
    ecosystem: str
    name: str
    version: str
    source: str
    direct: bool
    status: str = "ok"  # "ok", "error"
    notes: List[str] = field(default_factory=list)
    findings: List[VulnerabilityFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Severity & CVSS v3 Vector Helpers
# ---------------------------------------------------------------------------

def compute_cvss_v3_base_score(vector: Optional[str]) -> Optional[float]:
    """Compute numeric CVSS v3.0/v3.1 base score from a vector string (e.g. CVSS:3.1/AV:N/AC:L/...)."""
    if not vector or not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        return None
    metrics: Dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    s = metrics.get("S", "")
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("C", ""))
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("I", ""))
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("A", ""))
    if None in (av, ac, ui, c, i, a) or s not in ("U", "C"):
        return None

    pr_map = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if s == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    )
    pr = pr_map.get(metrics.get("PR", ""))
    if pr is None:
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))  # type: ignore[operator]
    if iss <= 0:
        return 0.0
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui  # type: ignore[operator]
    raw = impact + exploitability if s == "U" else 1.08 * (impact + exploitability)
    # Standard CVSS v3 roundup to 1 decimal place
    return min(10.0, math.ceil(round(raw * 100000) / 10000) / 10.0)


def normalize_severity(raw_sev: Optional[str], cvss: Optional[float] = None) -> str:
    if raw_sev:
        s = raw_sev.strip().upper()
        if s in SEVERITY_ORDER:
            return s
        if s == "MODERATE":
            return "MEDIUM"
    if cvss is not None:
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        if cvss > 0:
            return "LOW"
    return "UNKNOWN"


def clean_description(raw: Optional[str], max_len: int = 160) -> str:
    """Strip markdown headings/links, normalize whitespace, and truncate on word boundaries."""
    if not raw:
        return ""
    text = raw.strip()
    text = re.sub(
        r"(?im)^\s*#{1,6}\s*(?:summary|impact|description|details|overview|vulnerability)\b[:\s]*",
        "",
        text,
    )
    text = re.sub(r"#+\s*", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    cut = text[: max_len - 1]
    if " " in cut[max_len // 2 :]:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(".,;:- ") + "…"


def _http_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: int = 20,
) -> Any:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        if not raw.strip():
            return {}
        return json.loads(raw)


# ---------------------------------------------------------------------------
# Semver & Version Range Evaluators
# ---------------------------------------------------------------------------

def _parse_semver_tuple(ver_str: str) -> Optional[Tuple[int, int, int, str]]:
    """Extract (major, minor, patch, prerelease) from a tag/version string."""
    clean = re.sub(r"^(?:main[-_.]?|release[-_.]?)?[vV]?", "", ver_str.strip(), flags=re.I)
    m = re.match(
        r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?(rc\d*|alpha\d*|beta\d*|a\d+|b\d+|dev[.\d]*|pre[.\d]*|stable))?",
        clean,
        re.I,
    )
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    pre = (m.group(4) or "").lower()
    if pre == "stable":
        pre = ""
    return (major, minor, patch, pre)


def _format_semver_tuple(t: Tuple[int, int, int, str]) -> str:
    base = f"{t[0]}.{t[1]}.{t[2]}"
    return f"{base}-{t[3]}" if t[3] else base


def _prerelease_sort_key(pre: str) -> List[Tuple[int, Any]]:
    """Split a pre-release string like 'rc10' into numeric-aware comparable chunks."""
    parts: List[Tuple[int, Any]] = []
    for tok in re.findall(r"\d+|[a-z]+", pre.lower()):
        if tok.isdigit():
            parts.append((0, int(tok)))
        else:
            parts.append((1, tok))
    return parts


def _cmp_semver(
    a: Tuple[int, int, int, str] | str,
    b: Tuple[int, int, int, str] | str,
) -> int:
    if isinstance(a, str):
        parsed_a = _parse_semver_tuple(a)
        if parsed_a is None:
            return 0
        a = parsed_a
    if isinstance(b, str):
        parsed_b = _parse_semver_tuple(b)
        if parsed_b is None:
            return 0
        b = parsed_b
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    if a[3] == b[3]:
        return 0
    # Empty pre-release means stable release, which sorts higher than pre-release
    if not a[3]:
        return 1
    if not b[3]:
        return -1
    ka = _prerelease_sort_key(a[3])
    kb = _prerelease_sort_key(b[3])
    if ka == kb:
        return 0
    return -1 if ka < kb else 1


def pick_highest_fix_version(
    fix_strings: List[str],
    current_version: Optional[str] = None,
) -> str:
    """Compute the recommended upgrade version across a package's CVE fix strings.

    For each CVE (which may list fixes across multiple major/minor branches like '1.2.5, 2.0.1'),
    we pick the lowest fix version that is strictly greater than `current_version` (so a backport
    on the current branch is preferred over jumping a major version). Then across all CVEs for the
    package, we return the highest of those per-CVE minimal fixes.
    """
    cur_t = _parse_semver_tuple(current_version) if current_version else None
    per_cve_minimal_fixes: List[Tuple[Tuple[int, int, int, str], str]] = []
    raw_fallback: List[str] = []

    for raw in fix_strings:
        if not raw:
            continue
        cve_stable: List[Tuple[Tuple[int, int, int, str], str]] = []
        cve_any: List[Tuple[Tuple[int, int, int, str], str]] = []
        for part in re.split(r"[,;\s]+", raw):
            tok = part.strip().lstrip(">=<~")
            if not tok:
                continue
            if tok not in raw_fallback:
                raw_fallback.append(tok)
            parsed = _parse_semver_tuple(tok)
            if not parsed:
                continue
            if cur_t and _cmp_semver(parsed, cur_t) <= 0:
                continue
            clean_tok = tok.lstrip("vV")
            cve_any.append((parsed, clean_tok))
            if not parsed[3]:
                cve_stable.append((parsed, clean_tok))

        pool = cve_stable or cve_any
        if pool:
            pool.sort(key=lambda item: (item[0][:3], _prerelease_sort_key(item[0][3]) if item[0][3] else [(9, "")]))
            per_cve_minimal_fixes.append(pool[0])

    if per_cve_minimal_fixes:
        per_cve_minimal_fixes.sort(
            key=lambda item: (item[0][:3], _prerelease_sort_key(item[0][3]) if item[0][3] else [(9, "")])
        )
        return per_cve_minimal_fixes[-1][1]
    return raw_fallback[0] if raw_fallback else "unknown"


def _version_matches_cvenow_affected(ver_str: str, aff: Dict[str, Any]) -> bool:
    """Verify whether `ver_str` falls within a `cve.now` affected entry's versions or ranges."""
    clean_ver = ver_str.strip().lstrip("vV")
    versions_list = aff.get("versions") or []
    if versions_list:
        norm_versions = {str(v).strip().lstrip("vV") for v in versions_list if v}
        if clean_ver in norm_versions:
            return True

    target = _parse_semver_tuple(clean_ver)
    ranges = aff.get("ranges") or []
    if not target:
        # If version is non-semver and no explicit versions list disallowed it, allow if no ranges
        return not bool(versions_list)

    if not ranges:
        return not bool(versions_list)

    for rng in ranges:
        if not isinstance(rng, dict):
            continue
        intro = rng.get("introduced")
        fixed = rng.get("fixed")
        last_aff = rng.get("lastAffected")

        for ev in rng.get("events") or []:
            if isinstance(ev, dict):
                if "introduced" in ev and not intro:
                    intro = ev["introduced"]
                if "fixed" in ev and not fixed:
                    fixed = ev["fixed"]
                if "last_affected" in ev and not last_aff:
                    last_aff = ev["last_affected"]

        in_range = True
        if intro and str(intro) != "0":
            intro_t = _parse_semver_tuple(str(intro))
            if intro_t and _cmp_semver(target, intro_t) < 0:
                in_range = False
        if in_range and fixed:
            fixed_t = _parse_semver_tuple(str(fixed))
            if fixed_t and _cmp_semver(target, fixed_t) >= 0:
                in_range = False
        if in_range and last_aff:
            last_t = _parse_semver_tuple(str(last_aff))
            if last_t and _cmp_semver(target, last_t) > 0:
                in_range = False
        if in_range and (intro is not None or fixed is not None or last_aff is not None):
            return True

    return False


# ---------------------------------------------------------------------------
# 1. Harbor v2 Trivy Scanner (e.g. registry.nersc.gov)
# ---------------------------------------------------------------------------

def _is_harbor_v2_registry(registry_host: str, headers: Dict[str, str]) -> bool:
    """Probe `/api/v2.0/systeminfo` to verify if `registry_host` is a Harbor v2 instance."""
    if "nersc.gov" in registry_host or "harbor" in registry_host:
        return True
    try:
        info = _http_json(
            f"https://{registry_host}/api/v2.0/systeminfo",
            headers=headers,
            timeout=6,
        )
        return isinstance(info, dict) and (
            "harbor_version" in info or "registry_url" in info or "auth_mode" in info
        )
    except urllib.error.HTTPError as exc:
        return exc.code == 401
    except Exception:
        return False


def _extract_harbor_report(scan_overview: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(scan_overview, dict) or not scan_overview:
        return None
    for _mime, report in scan_overview.items():
        if isinstance(report, dict):
            return report
    return None


def scan_harbor_image(
    img: DiscoveredImage,
    res: ImageScanResult,
    trigger_if_unscanned: bool = True,
    scan_timeout: int = 45,
    quiet: bool = False,
) -> bool:
    """Query a Harbor v2 registry for Trivy scan results, triggering a scan if unscanned."""
    parts = img.repository.split("/", 1)
    if len(parts) < 2:
        return False
    project, repo_rest = parts[0], parts[1]
    repo_encoded = urllib.parse.quote(urllib.parse.quote(repo_rest, safe=""), safe="")
    ref = img.digest or img.tag or "latest"

    auth_header, auth_source = resolve_registry_auth(img.registry)
    res.auth_source = auth_source

    headers: Dict[str, str] = {
        "Accept": "application/json",
        "X-Accept-Vulnerabilities": (
            "application/vnd.security.vulnerability.report; version=1.1, "
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
        ),
    }
    if auth_header:
        headers["Authorization"] = auth_header

    if not _is_harbor_v2_registry(img.registry, headers):
        return False

    base_art_url = (
        f"https://{img.registry}/api/v2.0/projects/{project}"
        f"/repositories/{repo_encoded}/artifacts/{ref}"
    )

    try:
        art_data = _http_json(f"{base_art_url}?with_scan_overview=true", headers=headers)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            res.status = "auth_required"
            res.notes.append(
                f"Harbor API returned HTTP {exc.code} for {img.registry} "
                f"(login with `podman login {img.registry}` or `docker login {img.registry}`)"
            )
            return False
        if exc.code == 404:
            res.status = "not_found"
            res.notes.append(f"Artifact {img.raw} not found on Harbor registry {img.registry}")
            return False
        res.status = "error"
        res.notes.append(f"Harbor API error HTTP {exc.code} on {img.registry}")
        return False
    except Exception as exc:
        res.status = "error"
        res.notes.append(f"Harbor connection error: {exc}")
        return False

    res.digest = art_data.get("digest") or res.digest
    report = _extract_harbor_report(art_data.get("scan_overview"))
    scan_status = (report or {}).get("scan_status")

    if scan_status != "Success" and trigger_if_unscanned:
        if scan_status not in ("Running", "Pending", "Scheduled"):
            try:
                if not quiet:
                    print(
                        f"[regscout] Triggering Harbor Trivy scan for {img.raw} on {img.registry}...",
                        file=sys.stderr,
                    )
                req = urllib.request.Request(
                    f"{base_art_url}/scan",
                    data=b"{}",
                    headers={**headers, "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=15):
                    pass
                res.scan_triggered = True
            except Exception as exc:
                res.notes.append(f"Could not trigger Harbor scan: {exc}")

        deadline = time.time() + scan_timeout
        while time.time() < deadline:
            time.sleep(2.5)
            try:
                art_data = _http_json(f"{base_art_url}?with_scan_overview=true", headers=headers)
                report = _extract_harbor_report(art_data.get("scan_overview"))
                scan_status = (report or {}).get("scan_status")
                if scan_status == "Success":
                    break
                if scan_status in ("Error", "Failed", "Stopped"):
                    res.notes.append(f"Harbor scan ended with status: {scan_status}")
                    break
            except Exception:
                break

    if scan_status != "Success":
        res.status = "unscanned"
        res.notes.append(f"Harbor scan overview status is {scan_status or 'unscanned'}")
        return False

    vuln_href = ((art_data.get("addition_links") or {}).get("vulnerabilities") or {}).get("href")
    if not vuln_href:
        digest_ref = res.digest or ref
        vuln_href = (
            f"/api/v2.0/projects/{project}/repositories/{repo_encoded}"
            f"/artifacts/{digest_ref}/additions/vulnerabilities"
        )

    vuln_url = f"https://{img.registry}{vuln_href}"
    try:
        vdata = _http_json(vuln_url, headers=headers)
    except Exception as exc:
        res.status = "error"
        res.notes.append(f"Failed to fetch Harbor vulnerabilities addition: {exc}")
        return False

    res.status = "ok"
    res.scanners_used.append("harbor-trivy")
    seen = set()
    for _mime, rep_body in (vdata or {}).items():
        if not isinstance(rep_body, dict):
            continue
        scanner_info = rep_body.get("scanner") or {}
        scanner_label = f"harbor-{scanner_info.get('name', 'trivy').lower()}"
        for v in rep_body.get("vulnerabilities") or []:
            vid = v.get("id") or "UNKNOWN"
            pkg = v.get("package") or ""
            ver = v.get("version") or ""
            fix = v.get("fix_version") or None
            key = (vid, pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            cvss_v3 = (v.get("preferred_cvss") or {}).get("score_v3")
            sev = normalize_severity(v.get("severity"), cvss_v3)
            desc = clean_description(v.get("description"), 160)
            res.findings.append(
                VulnerabilityFinding(
                    id=vid,
                    severity=sev,
                    cvss=float(cvss_v3) if cvss_v3 is not None else None,
                    package=pkg,
                    version=ver,
                    fixed_by=fix,
                    title=desc or vid,
                    source=scanner_label,
                )
            )

    return True


# ---------------------------------------------------------------------------
# 2. Red Hat Quay Clair v4 Scanner (quay.io)
# ---------------------------------------------------------------------------

def scan_quay_image(
    img: DiscoveredImage,
    res: ImageScanResult,
    platform: str = "linux/amd64",
) -> bool:
    """Query Red Hat Quay's Clair API, resolving multi-arch manifest lists to `platform`."""
    repo = img.repository
    digest = img.digest
    target_os, _, target_arch = platform.partition("/")
    target_os = target_os or "linux"
    target_arch = target_arch or "amd64"

    try:
        if not digest:
            tag = img.tag or "latest"
            tag_url = (
                f"https://quay.io/api/v1/repository/{repo}/tag/"
                f"?specificTag={urllib.parse.quote(tag)}&onlyActiveTags=true"
            )
            tdata = _http_json(tag_url)
            tags = tdata.get("tags") or []
            if not tags:
                res.status = "not_found"
                res.notes.append(f"Tag '{tag}' not found on quay.io/{repo}")
                return False
            digest = tags[0].get("manifest_digest")

        if not digest:
            return False

        m_url = f"https://quay.io/api/v1/repository/{repo}/manifest/{digest}"
        mdata = _http_json(m_url)
        raw_manifest = mdata.get("manifest_data")
        if raw_manifest:
            parsed_manifest = json.loads(raw_manifest)
            for sub in parsed_manifest.get("manifests") or []:
                plat = sub.get("platform") or {}
                if plat.get("os") == target_os and plat.get("architecture") == target_arch:
                    digest = sub.get("digest") or digest
                    break

        res.digest = digest
        sec_url = f"https://quay.io/api/v1/repository/{repo}/manifest/{digest}/security?vulnerabilities=true"
        sdata = _http_json(sec_url)
        status = sdata.get("status")
        if status != "scanned":
            res.status = "unscanned"
            res.notes.append(f"Quay Clair security scan status: {status}")
            return False

        res.status = "ok"
        res.scanners_used.append("quay-clair")
        features = ((sdata.get("data") or {}).get("Layer") or {}).get("Features") or []
        seen = set()
        for feat in features:
            pkg_name = feat.get("Name") or ""
            pkg_ver = feat.get("Version") or ""
            for v in feat.get("Vulnerabilities") or []:
                vid = v.get("Name") or "UNKNOWN"
                key = (vid, pkg_name, pkg_ver)
                if key in seen:
                    continue
                seen.add(key)
                sev = normalize_severity(v.get("Severity"))
                fixed_by = v.get("FixedBy") or None
                desc = clean_description(v.get("Description"), 160)
                res.findings.append(
                    VulnerabilityFinding(
                        id=vid,
                        severity=sev,
                        cvss=None,
                        package=pkg_name,
                        version=pkg_ver,
                        fixed_by=fixed_by,
                        title=desc or vid,
                        source="quay-clair",
                    )
                )
        return True
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            res.status = "auth_required"
            res.notes.append(f"Quay API returned HTTP {exc.code} for quay.io/{repo}")
        elif exc.code == 404:
            res.status = "not_found"
            res.notes.append(f"Repository or manifest not found on quay.io/{repo}")
        else:
            res.status = "error"
            res.notes.append(f"Quay API HTTP {exc.code}: {exc}")
        return False
    except Exception as exc:
        res.status = "error"
        res.notes.append(f"Quay API error: {exc}")
        return False


# ---------------------------------------------------------------------------
# 3. Docker Hub + Docker Scout GraphQL Scanner (api.dso.docker.com)
# ---------------------------------------------------------------------------

def scan_docker_scout_image(
    img: DiscoveredImage,
    res: ImageScanResult,
    platform: str = "linux/amd64",
) -> bool:
    """Resolve platform digest via Docker Hub API and query Docker Scout GraphQL."""
    repo = img.repository
    digest = img.digest
    target_os, _, target_arch = platform.partition("/")
    target_os = target_os or "linux"
    target_arch = target_arch or "amd64"

    try:
        if not digest:
            tag = img.tag or "latest"
            hub_url = f"https://hub.docker.com/v2/repositories/{repo}/tags/{urllib.parse.quote(tag)}"
            tdata = _http_json(hub_url)
            for sub in tdata.get("images") or []:
                if sub.get("os") == target_os and sub.get("architecture") == target_arch:
                    digest = sub.get("digest")
                    break
            if not digest:
                digest = tdata.get("digest")

        if not digest:
            res.status = "unscanned"
            res.notes.append(f"Could not resolve manifest digest on Docker Hub for {img.raw}")
            return False
        res.digest = digest

        query = {
            "query": """
            query($digest: String!, $repo: String!) {
              imagePackagesForImageCoords(
                context: {}
                query: {
                  hostName: "hub.docker.com"
                  repoName: $repo
                  digest: $digest
                }
              ) {
                sbomState
                imagePackages {
                  packages {
                    package {
                      name
                      version
                      type
                      vulnerabilities {
                        sourceId
                        description
                        fixedBy
                        cvss {
                          severity
                          score
                        }
                      }
                    }
                  }
                }
              }
            }
            """,
            "variables": {"digest": digest, "repo": repo},
        }
        gdata = _http_json(
            "https://api.dso.docker.com/v1/graphql",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(query).encode("utf-8"),
        )
        coords = (gdata.get("data") or {}).get("imagePackagesForImageCoords")
        if not coords or coords.get("sbomState") != "INDEXED":
            return False

        res.status = "ok"
        res.scanners_used.append("docker-scout")
        pkgs = (coords.get("imagePackages") or {}).get("packages") or []
        seen = set()
        for item in pkgs:
            pkg = item.get("package") or {}
            pname = pkg.get("name") or ""
            pver = pkg.get("version") or ""
            for v in pkg.get("vulnerabilities") or []:
                vid = v.get("sourceId") or "UNKNOWN"
                key = (vid, pname, pver)
                if key in seen:
                    continue
                seen.add(key)
                cvss_obj = v.get("cvss") or {}
                score = cvss_obj.get("score")
                sev = normalize_severity(cvss_obj.get("severity"), score)
                desc = clean_description(v.get("description"), 160)
                res.findings.append(
                    VulnerabilityFinding(
                        id=vid,
                        severity=sev,
                        cvss=float(score) if score is not None else None,
                        package=pname,
                        version=pver,
                        fixed_by=v.get("fixedBy") or None,
                        title=desc or vid,
                        source="docker-scout",
                    )
                )
        return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            res.status = "not_found"
            res.notes.append(f"Image '{img.raw}' not found on Docker Hub")
        elif exc.code in (401, 403):
            res.status = "auth_required"
            res.notes.append(f"Docker Hub returned HTTP {exc.code} for '{img.raw}'")
        else:
            res.notes.append(f"Docker Scout HTTP {exc.code} for '{img.raw}'")
        return False
    except Exception as exc:
        res.notes.append(f"Docker Scout lookup error: {exc}")
        return False


# ---------------------------------------------------------------------------
# 4. OCI Registry Client + Zero-Pull OCI SBOM Attestation Scanner (OSV.dev)
# ---------------------------------------------------------------------------

def _oci_registry_get(
    registry_host: str,
    path: str,
    accept: str,
    auth_header: Optional[str] = None,
    cached_bearer: Optional[List[Optional[str]]] = None,
    timeout: int = 15,
    http_status_out: Optional[List[int]] = None,
) -> Optional[Dict[str, Any]]:
    """Perform an OCI Distribution v2 GET, negotiating Bearer token challenges if required."""
    api_host = "registry-1.docker.io" if registry_host == "docker.io" else registry_host
    url = f"https://{api_host}{path}"
    headers: Dict[str, str] = {"Accept": accept}
    if cached_bearer and cached_bearer[0]:
        headers["Authorization"] = f"Bearer {cached_bearer[0]}"
    elif auth_header:
        headers["Authorization"] = auth_header

    try:
        return _http_json(url, headers=headers, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            if http_status_out is not None:
                http_status_out.append(exc.code)
            return None
        www_auth = exc.headers.get("Www-Authenticate") or exc.headers.get("www-authenticate") or ""
        if not www_auth.lower().startswith("bearer "):
            if http_status_out is not None:
                http_status_out.append(401)
            return None
        realm_m = re.search(r'realm="([^"]+)"', www_auth)
        service_m = re.search(r'service="([^"]+)"', www_auth)
        scope_m = re.search(r'scope="([^"]+)"', www_auth)
        if not realm_m:
            if http_status_out is not None:
                http_status_out.append(401)
            return None
        q_params: Dict[str, str] = {}
        if service_m:
            q_params["service"] = service_m.group(1)
        if scope_m:
            q_params["scope"] = scope_m.group(1)
        tok_url = realm_m.group(1)
        if q_params:
            tok_url += ("&" if "?" in tok_url else "?") + urllib.parse.urlencode(q_params)
        tok_headers: Dict[str, str] = {}
        if auth_header:
            tok_headers["Authorization"] = auth_header
        try:
            tdata = _http_json(tok_url, headers=tok_headers, timeout=10)
            token = tdata.get("token") or tdata.get("access_token")
            if not token:
                if http_status_out is not None:
                    http_status_out.append(401)
                return None
            if cached_bearer is not None:
                cached_bearer[0] = token
            headers["Authorization"] = f"Bearer {token}"
            return _http_json(url, headers=headers, timeout=timeout)
        except urllib.error.HTTPError as retry_exc:
            if http_status_out is not None:
                http_status_out.append(retry_exc.code)
            return None
        except Exception:
            return None
    except Exception:
        return None


def extract_purls_from_sbom(sbom_doc: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Extract `(purl, package_name, package_version)` tuples from an SPDX or CycloneDX JSON document."""
    predicate = sbom_doc.get("predicate") if isinstance(sbom_doc.get("predicate"), dict) else sbom_doc
    if not isinstance(predicate, dict):
        return []

    extracted: List[Tuple[str, str, str]] = []
    seen_purls: Set[str] = set()

    # 1. SPDX 2.x format (`packages[].externalRefs`)
    for pkg in predicate.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        pname = str(pkg.get("name") or "")
        pver = str(pkg.get("versionInfo") or "")
        for ref in pkg.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceType") == "purl" and ref.get("referenceLocator"):
                purl = str(ref["referenceLocator"]).strip()
                if purl and purl not in seen_purls:
                    seen_purls.add(purl)
                    extracted.append((purl, pname, pver))

    # 2. CycloneDX format (`components[].purl`)
    for comp in predicate.get("components") or []:
        if not isinstance(comp, dict):
            continue
        purl = str(comp.get("purl") or "").strip()
        if purl and purl not in seen_purls:
            seen_purls.add(purl)
            extracted.append(
                (
                    purl,
                    str(comp.get("name") or ""),
                    str(comp.get("version") or ""),
                )
            )

    return extracted


def scan_oci_sbom_attestation(
    img: DiscoveredImage,
    res: ImageScanResult,
    platform: str = "linux/amd64",
    max_sbom_bytes: int = 25 * 1024 * 1024,
) -> bool:
    """Inspect OCI Image Index for a BuildKit/in-toto SBOM attestation and scan its PURLs via OSV.dev."""
    ref = img.digest or img.tag or "latest"
    auth_header, auth_source = resolve_registry_auth(img.registry)
    if auth_source and not res.auth_source:
        res.auth_source = auth_source
    cached_bearer: List[Optional[str]] = [None]

    target_os, _, target_arch = platform.partition("/")
    target_os = target_os or "linux"
    target_arch = target_arch or "amd64"

    manifest_accept = (
        "application/vnd.oci.image.index.v1+json, "
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.list.v2+json, "
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    http_status: List[int] = []
    index_data = _oci_registry_get(
        img.registry,
        f"/v2/{img.repository}/manifests/{ref}",
        manifest_accept,
        auth_header=auth_header,
        cached_bearer=cached_bearer,
        http_status_out=http_status,
    )
    if not isinstance(index_data, dict):
        if 404 in http_status and res.status == "ok":
            res.status = "not_found"
            res.notes.append(f"Image '{img.raw}' not found on {img.registry} (HTTP 404)")
        elif any(c in (401, 403) for c in http_status) and res.status == "ok":
            res.status = "auth_required"
            res.notes.append(f"Registry {img.registry} returned HTTP {http_status[-1]} for '{img.raw}'")
        return False

    manifests = index_data.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        return False

    target_digest: Optional[str] = None
    for sub in manifests:
        plat = sub.get("platform") or {}
        if plat.get("os") == target_os and plat.get("architecture") == target_arch:
            target_digest = sub.get("digest")
            break

    att_digest: Optional[str] = None
    for sub in manifests:
        ann = sub.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            ref_dig = ann.get("vnd.docker.reference.digest")
            if target_digest and ref_dig == target_digest:
                att_digest = sub.get("digest")
                break
            if not att_digest:
                att_digest = sub.get("digest")

    if not att_digest:
        return False

    att_manifest = _oci_registry_get(
        img.registry,
        f"/v2/{img.repository}/manifests/{att_digest}",
        "application/vnd.oci.image.manifest.v1+json, application/json",
        auth_header=auth_header,
        cached_bearer=cached_bearer,
    )
    if not isinstance(att_manifest, dict):
        return False

    sbom_blob_digest: Optional[str] = None
    for layer in att_manifest.get("layers") or []:
        if not isinstance(layer, dict):
            continue
        pred_type = ((layer.get("annotations") or {}).get("in-toto.io/predicate-type") or "").lower()
        media_type = (layer.get("mediaType") or "").lower()
        size = int(layer.get("size") or 0)
        if ("spdx" in pred_type or "cyclonedx" in pred_type or "spdx" in media_type or "cyclonedx" in media_type):
            if 0 < size <= max_sbom_bytes:
                sbom_blob_digest = layer.get("digest")
                break

    if not sbom_blob_digest:
        return False

    sbom_doc = _oci_registry_get(
        img.registry,
        f"/v2/{img.repository}/blobs/{sbom_blob_digest}",
        "application/vnd.in-toto+json, application/json",
        auth_header=auth_header,
        cached_bearer=cached_bearer,
        timeout=30,
    )
    if not isinstance(sbom_doc, dict):
        return False

    purl_tuples = extract_purls_from_sbom(sbom_doc)
    if not purl_tuples:
        return False

    osv_findings, osv_errors = query_osv_purls(purl_tuples, source_label="oci-sbom-osv")
    if osv_errors:
        res.notes.extend(osv_errors)
        return False

    if target_digest and not res.digest:
        res.digest = target_digest
    res.status = "ok"
    res.scanners_used.append("oci-sbom-osv")
    res.findings.extend(osv_findings)
    return True


# ---------------------------------------------------------------------------
# 5. Local Trivy CLI Fallback (`trivy image` and `trivy fs`)
# ---------------------------------------------------------------------------

_TRIVY_TYPE_ECOSYSTEM_MAP: Dict[str, str] = {
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "uv": "pypi",
    "python-pkg": "pypi",
    "gomod": "go",
    "gobinary": "go",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "node-pkg": "npm",
    "cargo": "crates.io",
    "bundler": "rubygems",
    "gemspec": "rubygems",
    "composer": "packagist",
    "pom": "maven",
    "gradle": "maven",
    "jar": "maven",
    "nuget": "nuget",
    "dotnet-core": "nuget",
    "packages-props": "nuget",
    "cocoapods": "cocoapods",
    "swift": "swift",
    "hex": "hex",
    "pub": "pub",
}


def _extract_trivy_cvss(vuln: Dict[str, Any]) -> Optional[float]:
    """Extract the most authoritative CVSS score from a Trivy vulnerability object."""
    cvss_map = vuln.get("CVSS")
    if not isinstance(cvss_map, dict) or not cvss_map:
        return None

    sev_source = str(vuln.get("SeveritySource") or "").lower()
    ordered_sources: List[str] = []
    for preferred in (sev_source, "nvd", "ghsa", "redhat", "ubuntu", "wolfi", "chainguard"):
        if preferred and preferred in cvss_map and preferred not in ordered_sources:
            ordered_sources.append(preferred)
    for k in cvss_map:
        if k not in ordered_sources:
            ordered_sources.append(k)

    for src in ordered_sources:
        entry = cvss_map.get(src)
        if not isinstance(entry, dict):
            continue
        for score_key in ("V3Score", "V40Score", "V4Score", "V2Score"):
            val = entry.get(score_key)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
        vec = entry.get("V3Vector")
        if isinstance(vec, str):
            calc = compute_cvss_v3_base_score(vec)
            if calc is not None:
                return calc
    return None


def _parse_trivy_vulnerabilities(
    results_list: List[Dict[str, Any]],
    source_label: str = "trivy-local",
) -> List[VulnerabilityFinding]:
    """Convert Trivy JSON `Results[].Vulnerabilities[]` entries into `VulnerabilityFinding` objects."""
    findings: List[VulnerabilityFinding] = []
    seen: Set[Tuple[str, str, str]] = set()

    for target_res in results_list:
        if not isinstance(target_res, dict):
            continue
        for v in target_res.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            vid = str(v.get("VulnerabilityID") or "UNKNOWN")
            pkg = str(v.get("PkgName") or "")
            ver = str(v.get("InstalledVersion") or "")
            fix_raw = v.get("FixedVersion")
            fix = str(fix_raw).strip() if fix_raw else None
            key = (vid, pkg, ver)
            if key in seen:
                continue
            seen.add(key)

            aliases = [
                str(a)
                for a in (v.get("VendorIDs") or [])
                if a and str(a) != vid
            ]
            cvss = _extract_trivy_cvss(v)
            sev = normalize_severity(v.get("Severity"), cvss)
            desc = clean_description(v.get("Title") or v.get("Description"), 160)
            findings.append(
                VulnerabilityFinding(
                    id=vid,
                    severity=sev,
                    cvss=cvss,
                    package=pkg,
                    version=ver,
                    fixed_by=fix,
                    title=desc or vid,
                    source=source_label,
                    aliases=aliases,
                )
            )
    return findings


def _extract_trivy_purls(
    results_list: List[Dict[str, Any]],
) -> List[Tuple[str, str, str]]:
    """Extract `(purl, pkg_name, pkg_version)` tuples (including OS source package PURLs) from Trivy Results."""
    purl_tuples: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    for target_res in results_list:
        if not isinstance(target_res, dict):
            continue
        for pkg in target_res.get("Packages") or []:
            if not isinstance(pkg, dict):
                continue
            pname = str(pkg.get("Name") or "").strip()
            pver = str(pkg.get("Version") or "").strip()
            purl = str((pkg.get("Identifier") or {}).get("PURL") or "").strip()
            if not purl or not pname:
                continue
            if (purl, pname) not in seen:
                seen.add((purl, pname))
                purl_tuples.append((purl, pname, pver))

            # Distro OSV advisories (Wolfi/Chainguard, Alpine, Debian, Ubuntu) are indexed by source package name
            src_name = str(pkg.get("SrcName") or "").strip()
            src_ver = str(pkg.get("SrcVersion") or pver).strip()
            if (
                src_name
                and src_name != pname
                and purl.startswith(("pkg:apk/", "pkg:deb/", "pkg:rpm/"))
                and f"/{pname}@" in purl
            ):
                prefix, _, suffix = purl.partition(f"/{pname}@")
                q_part = ("?" + suffix.split("?", 1)[1]) if "?" in suffix else ""
                src_purl = f"{prefix}/{src_name}@{urllib.parse.quote(src_ver, safe='.-_+')}{q_part}"
                if (src_purl, pname) not in seen:
                    seen.add((src_purl, pname))
                    purl_tuples.append((src_purl, pname, pver))

    return purl_tuples


def scan_local_trivy_image(
    img: DiscoveredImage,
    res: ImageScanResult,
    platform: str = "linux/amd64",
    scan_timeout: int = 300,
    quiet: bool = False,
    allow_local_trivy: bool = True,
) -> bool:
    """Fallback to local `trivy image` (+ OSV.dev PURL enrichment) when an image has no registry scan or OCI SBOM."""
    if not allow_local_trivy:
        if res.status not in ("auth_required", "not_found", "error"):
            res.status = "unscanned"
        res.notes.append(
            "No registry scanner API or OCI SBOM attestation found (--no-local-trivy disabled local Trivy fallback)"
        )
        return False

    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        if res.status not in ("auth_required", "not_found", "error"):
            res.status = "unscanned"
        res.notes.append(
            "No registry scanner API or OCI SBOM attestation found, and local 'trivy' binary is not installed "
            "(install with `brew install trivy` to scan unindexed images)"
        )
        return False

    if not quiet:
        print(
            f"[regscout] No registry scan or OCI SBOM for {img.raw}; running local 'trivy image' scan...",
            file=sys.stderr,
        )

    cmd = [
        trivy_bin,
        "image",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--format",
        "json",
        "--quiet",
        "--platform",
        platform,
        img.raw,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=scan_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if res.status not in ("auth_required", "not_found", "error"):
            res.status = "error"
        res.notes.append(f"Local 'trivy image' timed out after {scan_timeout}s for {img.raw}")
        return False
    except Exception as exc:
        if res.status not in ("auth_required", "not_found", "error"):
            res.status = "error"
        res.notes.append(f"Failed to execute local 'trivy image': {exc}")
        return False

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        err_text = clean_description(proc.stderr or proc.stdout or f"exit code {proc.returncode}", 200)
        err_upper = err_text.upper()
        if any(tok in err_upper for tok in ("UNAUTHORIZED", "401", "403", "DENIED", "AUTHENTICATION")):
            res.status = "auth_required"
        elif any(tok in err_upper for tok in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN", "NOT FOUND", "404")):
            res.status = "not_found"
        elif res.status not in ("auth_required", "not_found"):
            res.status = "error"
        res.notes.append(f"Local 'trivy image' failed: {err_text}")
        return False

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        res.status = "error"
        res.notes.append(f"Failed to parse local 'trivy image' JSON output: {exc}")
        return False

    if not isinstance(data, dict):
        res.status = "error"
        res.notes.append("Unexpected JSON root from local 'trivy image'")
        return False

    metadata = data.get("Metadata") or {}
    if not res.digest and isinstance(metadata, dict):
        for rd in metadata.get("RepoDigests") or []:
            if isinstance(rd, str) and "@sha256:" in rd:
                res.digest = "sha256:" + rd.split("@sha256:", 1)[1]
                break

    results_list = data.get("Results") or []
    trivy_findings = _parse_trivy_vulnerabilities(results_list, source_label="trivy-local")

    # Cross-check extracted OS/language PURLs against live OSV.dev so 0-day distro advisories
    # published after the last Trivy DB snapshot are still caught immediately.
    purl_tuples = _extract_trivy_purls(results_list)
    osv_findings: List[VulnerabilityFinding] = []
    if purl_tuples:
        osv_findings, _ = query_osv_purls(purl_tuples, source_label="osv.dev")

    res.status = "ok"
    res.scanners_used.append("trivy-local")
    if osv_findings:
        res.scanners_used.append("osv.dev")
        # Group by (package, version) before merging so same CVE on different subpackages isn't collapsed prematurely
        by_pkg: Dict[Tuple[str, str], Tuple[List[VulnerabilityFinding], List[VulnerabilityFinding]]] = {}
        for f in trivy_findings:
            by_pkg.setdefault((f.package, f.version), ([], []))[0].append(f)
        for f in osv_findings:
            by_pkg.setdefault((f.package, f.version), ([], []))[1].append(f)
        for _k, (t_list, o_list) in by_pkg.items():
            res.findings.extend(merge_findings(t_list, o_list))
    else:
        res.findings.extend(trivy_findings)
    return True


def scan_local_trivy_fs(
    target_path: str,
    scan_timeout: int = 180,
    quiet: bool = False,
) -> Tuple[List[PackageScanResult], List[str]]:
    """Scan a directory or third-party lockfile via `trivy fs --scanners vuln --format json`."""
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        raise ValueError(
            f"Unsupported lockfile or directory '{target_path}' for built-in parser "
            "(supported built-in lockfiles: go.mod, *requirements*.txt, constraints*.txt, "
            "uv.lock, poetry.lock, package-lock.json, Cargo.lock; or install `trivy` via `brew install trivy`)"
        )

    if not quiet:
        print(
            f"[regscout] Running local 'trivy fs' vulnerability scan on {target_path}...",
            file=sys.stderr,
        )

    cmd = [
        trivy_bin,
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--quiet",
        target_path,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=scan_timeout,
            check=False,
        )
    except Exception as exc:
        return [
            PackageScanResult(
                ecosystem="trivy-fs",
                name=os.path.basename(os.path.abspath(target_path)) or target_path,
                version="unknown",
                source=target_path,
                direct=True,
                status="error",
                notes=[f"Local 'trivy fs' failed: {exc}"],
            )
        ], []

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        err_text = clean_description(proc.stderr or proc.stdout or f"exit code {proc.returncode}", 200)
        return [
            PackageScanResult(
                ecosystem="trivy-fs",
                name=os.path.basename(os.path.abspath(target_path)) or target_path,
                version="unknown",
                source=target_path,
                direct=True,
                status="error",
                notes=[f"Local 'trivy fs' failed: {err_text}"],
            )
        ], []

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        return [
            PackageScanResult(
                ecosystem="trivy-fs",
                name=os.path.basename(os.path.abspath(target_path)) or target_path,
                version="unknown",
                source=target_path,
                direct=True,
                status="error",
                notes=[f"Failed to parse 'trivy fs' JSON: {exc}"],
            )
        ], []

    results_list = data.get("Results") or []
    if not results_list:
        warnings = [
            f"Local 'trivy fs' found no supported dependency lockfiles in '{target_path}'"
        ]
        return [], warnings

    pkg_map: Dict[Tuple[str, str, str], PackageScanResult] = {}
    for target_res in results_list:
        if not isinstance(target_res, dict):
            continue
        raw_type = str(target_res.get("Type") or "").lower()
        eco = _TRIVY_TYPE_ECOSYSTEM_MAP.get(raw_type, raw_type or "unknown")
        target_label = str(target_res.get("Target") or os.path.basename(target_path))

        for pkg in target_res.get("Packages") or []:
            if not isinstance(pkg, dict):
                continue
            rel = str(pkg.get("Relationship") or "").lower()
            if rel == "root":
                continue
            pname = str(pkg.get("Name") or "").strip()
            pver = str(pkg.get("Version") or "").strip().lstrip("vV")
            if not pname or not pver:
                continue
            key = (eco, pname, pver)
            if key not in pkg_map:
                pkg_map[key] = PackageScanResult(
                    ecosystem=eco,
                    name=pname,
                    version=pver,
                    source=target_label,
                    direct=(rel != "indirect"),
                    status="ok",
                )

        findings = _parse_trivy_vulnerabilities([target_res], source_label="trivy-local")
        for f in findings:
            clean_ver = f.version.strip().lstrip("vV")
            key = (eco, f.package, clean_ver)
            if key not in pkg_map:
                pkg_map[key] = PackageScanResult(
                    ecosystem=eco,
                    name=f.package,
                    version=clean_ver,
                    source=target_label,
                    direct=True,
                    status="ok",
                )
            pkg_map[key].findings.append(f)

    return list(pkg_map.values()), []


# ---------------------------------------------------------------------------
# 6. OSV.dev API (`/v1/querybatch` + `/v1/vulns/<id>`)
# ---------------------------------------------------------------------------

def _parse_osv_vuln_detail(
    vuln: Dict[str, Any],
    pkg_name: str,
    pkg_ver: str,
    source_label: str = "osv.dev",
) -> VulnerabilityFinding:
    raw_id = vuln.get("id") or "UNKNOWN"
    raw_aliases = list(
        dict.fromkeys(
            str(a)
            for a in ((vuln.get("aliases") or []) + (vuln.get("upstream") or []))
            if a
        )
    )
    # Prefer CVE-* as primary display ID if present in aliases or upstream
    cve_aliases = [a for a in raw_aliases if a.upper().startswith("CVE-")]
    if not raw_id.upper().startswith("CVE-") and cve_aliases:
        primary_id = cve_aliases[0]
        aliases = [raw_id] + [a for a in raw_aliases if a != primary_id]
    else:
        primary_id = raw_id
        aliases = raw_aliases

    cvss_score: Optional[float] = None
    for sev_entry in vuln.get("severity") or []:
        if isinstance(sev_entry, dict) and sev_entry.get("score"):
            score_str = str(sev_entry["score"])
            try:
                cvss_score = float(score_str)
                break
            except ValueError:
                calc = compute_cvss_v3_base_score(score_str)
                if calc is not None:
                    cvss_score = calc
                    break

    db_sev = (vuln.get("database_specific") or {}).get("severity")
    fixed_versions: List[str] = []
    fallback_fixed: List[str] = []
    fallback_db_sev: Optional[str] = None
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        aff_pkg = (aff.get("package") or {}).get("name") or ""
        aff_sev = (aff.get("database_specific") or {}).get("severity") or (
            aff.get("ecosystem_specific") or {}
        ).get("severity")
        if not fallback_db_sev and aff_sev:
            fallback_db_sev = aff_sev
        aff_fixes: List[str] = []
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    aff_fixes.append(str(ev["fixed"]))
        fallback_fixed.extend(aff_fixes)
        if aff_pkg and pkg_name and aff_pkg.lower() != pkg_name.lower():
            continue
        if not db_sev and aff_sev:
            db_sev = aff_sev
        fixed_versions.extend(aff_fixes)

    if not fixed_versions and fallback_fixed:
        # When an OS binary subpackage (e.g. libbrotlidec1) matched via its source package PURL (brotli),
        # use the source package's fixed_versions from the distro advisory.
        fixed_versions = fallback_fixed
    if not db_sev and fallback_db_sev:
        db_sev = fallback_db_sev

    dedup_fixed = list(dict.fromkeys(fixed_versions))
    fixed_by = ", ".join(dedup_fixed) if dedup_fixed else None
    sev = normalize_severity(db_sev, cvss_score)
    summary = clean_description(vuln.get("summary") or vuln.get("details"), 160)

    return VulnerabilityFinding(
        id=primary_id,
        severity=sev,
        cvss=cvss_score,
        package=pkg_name,
        version=pkg_ver,
        fixed_by=fixed_by,
        title=summary or primary_id,
        source=source_label,
        aliases=aliases,
    )


def _hydrate_osv_ids(vuln_ids: Set[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch full OSV vulnerability records concurrently for unique matched IDs (plus upstream enrichment for distro stubs)."""
    if not vuln_ids:
        return {}
    details: Dict[str, Dict[str, Any]] = {}

    def _fetch_one(vid: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        try:
            data = _http_json(
                f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}",
                timeout=15,
            )
            return vid, data if isinstance(data, dict) else None
        except Exception:
            return vid, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for vid, doc in pool.map(_fetch_one, sorted(vuln_ids)):
            if doc:
                details[vid] = doc

        # Distro advisories (e.g. Wolfi/Chainguard CGA-*, Alpine, Debian) often omit severity/summary
        # and point to upstream GHSA-*/CVE-* records that carry the canonical description and severity.
        upstream_to_fetch: Set[str] = set()
        for doc in details.values():
            has_sev = bool(doc.get("severity") or (doc.get("database_specific") or {}).get("severity"))
            has_desc = bool(doc.get("summary") or doc.get("details"))
            if not has_sev or not has_desc:
                for up_id in doc.get("upstream") or []:
                    if isinstance(up_id, str) and up_id not in details:
                        upstream_to_fetch.add(up_id)

        if upstream_to_fetch:
            upstream_docs: Dict[str, Dict[str, Any]] = {}
            for up_id, up_doc in pool.map(_fetch_one, sorted(upstream_to_fetch)):
                if up_doc:
                    upstream_docs[up_id] = up_doc

            for doc in details.values():
                for up_id in doc.get("upstream") or []:
                    up_doc = upstream_docs.get(up_id) or details.get(up_id)
                    if not up_doc:
                        continue
                    if not doc.get("summary") and up_doc.get("summary"):
                        doc["summary"] = up_doc["summary"]
                    if not doc.get("details") and up_doc.get("details"):
                        doc["details"] = up_doc["details"]
                    if not doc.get("severity") and up_doc.get("severity"):
                        doc["severity"] = up_doc["severity"]
                    up_db_sev = (up_doc.get("database_specific") or {}).get("severity")
                    if up_db_sev and not (doc.get("database_specific") or {}).get("severity"):
                        doc.setdefault("database_specific", {})["severity"] = up_db_sev

    return details


def query_osv_purls(
    purl_tuples: List[Tuple[str, str, str]],
    source_label: str = "oci-sbom-osv",
) -> Tuple[List[VulnerabilityFinding], List[str]]:
    """Batch-query OSV.dev for `(purl, pkg_name, pkg_version)` tuples extracted from an SBOM."""
    findings: List[VulnerabilityFinding] = []
    errors: List[str] = []
    if not purl_tuples:
        return findings, errors

    batch_size = 500
    matched_per_item: List[Tuple[str, str, List[str]]] = []
    unique_ids: Set[str] = set()

    for idx in range(0, len(purl_tuples), batch_size):
        chunk = purl_tuples[idx : idx + batch_size]
        payload = {"queries": [{"package": {"purl": purl}} for purl, _n, _v in chunk]}
        try:
            resp = _http_json(
                "https://api.osv.dev/v1/querybatch",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps(payload).encode("utf-8"),
                timeout=25,
            )
        except Exception as exc:
            errors.append(f"OSV.dev querybatch failed: {exc}")
            continue

        results_list = resp.get("results") or []
        for (purl, pname, pver), res_item in zip(chunk, results_list):
            vlist = (res_item or {}).get("vulns") or []
            vids = [str(v["id"]) for v in vlist if isinstance(v, dict) and v.get("id")]
            if vids:
                display_name = pname or purl
                matched_per_item.append((display_name, pver, vids))
                unique_ids.update(vids)

    details_map = _hydrate_osv_ids(unique_ids)
    seen_keys: Set[Tuple[str, str, str]] = set()
    for pname, pver, vids in matched_per_item:
        for vid in vids:
            doc = details_map.get(vid)
            if not doc:
                continue
            finding = _parse_osv_vuln_detail(doc, pname, pver, source_label=source_label)
            dedup_key = (finding.id, pname, pver)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                findings.append(finding)

    return findings, errors


def query_osv_batch(
    specs: List[Tuple[str, str, str]],
) -> Tuple[Dict[Tuple[str, str, str], List[VulnerabilityFinding]], List[str]]:
    """Query `https://api.osv.dev/v1/querybatch` for `(ecosystem, name, version)` tuples."""
    results: Dict[Tuple[str, str, str], List[VulnerabilityFinding]] = {s: [] for s in specs}
    errors: List[str] = []
    if not specs:
        return results, errors

    unique_specs = list(dict.fromkeys(specs))
    batch_size = 500
    spec_to_vids: Dict[Tuple[str, str, str], List[str]] = {s: [] for s in unique_specs}
    unique_ids: Set[str] = set()

    for idx in range(0, len(unique_specs), batch_size):
        batch = unique_specs[idx : idx + batch_size]
        queries = []
        for eco, name, ver in batch:
            osv_eco = OSV_ECOSYSTEM_MAP.get(eco.lower(), eco)
            queries.append(
                {
                    "package": {"name": name, "ecosystem": osv_eco},
                    "version": ver,
                }
            )
        try:
            resp = _http_json(
                "https://api.osv.dev/v1/querybatch",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"queries": queries}).encode("utf-8"),
                timeout=25,
            )
        except Exception as exc:
            errors.append(f"OSV.dev querybatch error: {exc}")
            continue

        for spec, item in zip(batch, resp.get("results") or []):
            vids = [
                str(v["id"])
                for v in ((item or {}).get("vulns") or [])
                if isinstance(v, dict) and v.get("id")
            ]
            if vids:
                spec_to_vids[spec].extend(vids)
                unique_ids.update(vids)

    details_map = _hydrate_osv_ids(unique_ids)
    for spec, vids in spec_to_vids.items():
        _eco, s_name, s_ver = spec
        seen_ids: Set[str] = set()
        for vid in vids:
            doc = details_map.get(vid)
            if not doc:
                continue
            finding = _parse_osv_vuln_detail(doc, s_name, s_ver, source_label="osv.dev")
            if finding.id not in seen_ids:
                seen_ids.add(finding.id)
                results[spec].append(finding)

    return results, errors


# ---------------------------------------------------------------------------
# 7. cve.now Stack API (https://cve.now/stack?p=...&format=json)
# ---------------------------------------------------------------------------

def query_cve_now_batch(
    specs: List[Tuple[str, str, str]],
) -> Tuple[Dict[Tuple[str, str, str], List[VulnerabilityFinding]], List[str]]:
    """Query `https://cve.now/stack` with strict per-version matching."""
    results: Dict[Tuple[str, str, str], List[VulnerabilityFinding]] = {s: [] for s in specs}
    errors: List[str] = []
    if not specs:
        return results, errors

    unique_specs = list(dict.fromkeys(specs))
    batch_size = 35
    seen_per_spec: Dict[Tuple[str, str, str], Dict[str, VulnerabilityFinding]] = {
        s: {} for s in unique_specs
    }

    for idx in range(0, len(unique_specs), batch_size):
        batch = unique_specs[idx : idx + batch_size]
        p_arg = ",".join(f"{eco}:{name}@{ver}" for eco, name, ver in batch)
        url = f"https://cve.now/stack?p={urllib.parse.quote(p_arg, safe=':,@/_.-')}&format=json"
        try:
            data = _http_json(url, timeout=25)
        except Exception as exc:
            errors.append(f"cve.now batch query failed: {exc}")
            continue

        for entry in data.get("entries") or []:
            vid = entry.get("id") or "UNKNOWN"
            aliases = [str(a) for a in (entry.get("aliases") or []) if a]
            title = (entry.get("title") or "").strip()
            if title.startswith(f"{vid}:"):
                title = title[len(vid) + 1 :].strip()
            title = clean_description(title, 160)
            cvss = (entry.get("severity") or {}).get("cvss")
            sev = normalize_severity(entry.get("statedSeverity"), cvss)

            matched_meta = entry.get("matched") or {}
            matched_ver = str(matched_meta.get("version") or "").strip().lstrip("vV")

            for aff in entry.get("affected") or []:
                aff_eco_raw = aff.get("ecosystem") or ""
                aff_eco = (normalize_ecosystem(aff_eco_raw) or aff_eco_raw).lower()
                aff_pkg = (aff.get("package") or "").lower()
                fixed_list = list(aff.get("fixed") or [])
                for rng in aff.get("ranges") or []:
                    if isinstance(rng, dict) and rng.get("fixed"):
                        fixed_list.append(str(rng["fixed"]))
                    for ev in (rng.get("events") if isinstance(rng, dict) else None) or []:
                        if isinstance(ev, dict) and ev.get("fixed"):
                            fixed_list.append(str(ev["fixed"]))
                dedup_fixed = list(dict.fromkeys(str(x) for x in fixed_list if x))
                fixed_by = ", ".join(dedup_fixed) if dedup_fixed else None

                for spec in batch:
                    s_eco, s_name, s_ver = spec
                    if s_eco.lower() != aff_eco or s_name.lower() != aff_pkg:
                        continue
                    # Enforce version-specific matching so CVEs never leak across versions in the batch
                    clean_s_ver = s_ver.strip().lstrip("vV")
                    if matched_ver and clean_s_ver != matched_ver:
                        if not _version_matches_cvenow_affected(clean_s_ver, aff):
                            continue
                    elif not _version_matches_cvenow_affected(clean_s_ver, aff):
                        continue

                    existing = seen_per_spec[spec].get(vid)
                    if existing:
                        if not existing.fixed_by and fixed_by:
                            existing.fixed_by = fixed_by
                    else:
                        finding = VulnerabilityFinding(
                            id=vid,
                            severity=sev,
                            cvss=float(cvss) if cvss is not None else None,
                            package=s_name,
                            version=s_ver,
                            fixed_by=fixed_by,
                            title=title or vid,
                            source="cve.now",
                            aliases=aliases,
                        )
                        seen_per_spec[spec][vid] = finding
                        results[spec].append(finding)

    return results, errors


def merge_findings(
    primary_list: List[VulnerabilityFinding],
    secondary_list: List[VulnerabilityFinding],
) -> List[VulnerabilityFinding]:
    """Merge and deduplicate findings from multiple sources (e.g. OSV.dev + cve.now) by ID and aliases."""
    merged: List[VulnerabilityFinding] = []
    known_ids: Dict[str, VulnerabilityFinding] = {}

    for f in list(primary_list) + list(secondary_list):
        all_keys = [f.id.upper()] + [a.upper() for a in f.aliases]
        matched_existing: Optional[VulnerabilityFinding] = None
        for k in all_keys:
            if k in known_ids:
                matched_existing = known_ids[k]
                break

        if matched_existing is not None:
            # Enrich existing finding if secondary source has CVSS, fixed_by, or CVE ID
            if matched_existing.cvss is None and f.cvss is not None:
                matched_existing.cvss = f.cvss
                matched_existing.severity = normalize_severity(
                    matched_existing.severity, f.cvss
                )
            if not matched_existing.fixed_by and f.fixed_by:
                matched_existing.fixed_by = f.fixed_by
            elif matched_existing.fixed_by and f.fixed_by and f.fixed_by not in matched_existing.fixed_by:
                combined = list(
                    dict.fromkeys(
                        re.split(r"[,;\s]+", f"{matched_existing.fixed_by}, {f.fixed_by}")
                    )
                )
                matched_existing.fixed_by = ", ".join(x for x in combined if x)
            if not matched_existing.id.upper().startswith("CVE-") and f.id.upper().startswith("CVE-"):
                if matched_existing.id not in matched_existing.aliases:
                    matched_existing.aliases.append(matched_existing.id)
                matched_existing.id = f.id
            for a in all_keys:
                known_ids[a] = matched_existing
        else:
            merged.append(f)
            for k in all_keys:
                known_ids[k] = f

    return merged


def query_packages_multi_source(
    specs: List[Tuple[str, str, str]],
) -> Tuple[Dict[Tuple[str, str, str], List[VulnerabilityFinding]], List[str]]:
    """Query both `OSV.dev` and `cve.now` for `(ecosystem, name, version)` tuples and merge results."""
    results: Dict[Tuple[str, str, str], List[VulnerabilityFinding]] = {s: [] for s in specs}
    if not specs:
        return results, []

    osv_res, osv_errs = query_osv_batch(specs)
    cvenow_res, cvenow_errs = query_cve_now_batch(specs)

    for s in specs:
        results[s] = merge_findings(cvenow_res.get(s, []), osv_res.get(s, []))

    # Only report a fatal error if both sources failed
    fatal_errors: List[str] = []
    if osv_errs and cvenow_errs:
        fatal_errors.extend(osv_errs)
        fatal_errors.extend(cvenow_errs)

    return results, fatal_errors
