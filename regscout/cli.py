"""CLI entrypoint and output formatters (text, json, markdown) for regscout."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from regscout import __version__
from regscout.discovery import is_trivy_fs_target, resolve_explicit_targets
from regscout.scanners import (
    ImageScanResult,
    PackageScanResult,
    SEVERITY_ORDER,
    VulnerabilityFinding,
    clean_description,
    pick_highest_fix_version,
    query_packages_multi_source,
    scan_docker_scout_image,
    scan_harbor_image,
    scan_local_trivy_fs,
    scan_local_trivy_image,
    scan_oci_sbom_attestation,
    scan_quay_image,
)


class _Styler:
    """ANSI terminal color helper that pads plain text before applying escape codes."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red_bold(self, text: str) -> str:
        return self._wrap("1;31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def green_bold(self, text: str) -> str:
        return self._wrap("1;32", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def severity(self, sev: str, width: int = 0) -> str:
        s = sev.upper()
        padded = s.ljust(width) if width else s
        if s == "CRITICAL":
            return self.red_bold(padded)
        if s == "HIGH":
            return self.yellow(padded)
        if s == "MEDIUM":
            return self.cyan(padded)
        return self.dim(padded)


def _should_use_color(color_mode: str) -> bool:
    if color_mode == "always":
        return True
    if color_mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _filter_findings(
    findings: List[VulnerabilityFinding],
    min_sev_rank: int,
    fixable_only: bool,
) -> List[VulnerabilityFinding]:
    filtered: List[VulnerabilityFinding] = []
    for f in findings:
        rank = SEVERITY_ORDER.get(f.severity.upper(), 0)
        if rank < min_sev_rank:
            continue
        if fixable_only and not f.fixed_by:
            continue
        filtered.append(f)
    filtered.sort(
        key=lambda x: (
            -SEVERITY_ORDER.get(x.severity.upper(), 0),
            -(x.cvss or 0.0),
            0 if x.fixed_by else 1,
            x.id,
        )
    )
    return filtered


def _severity_counts(findings: List[VulnerabilityFinding]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.severity.upper()
        counts[sev if sev in counts else "UNKNOWN"] += 1
    return counts


def _collapse_subpackage_findings(
    findings: List[VulnerabilityFinding],
) -> List[VulnerabilityFinding]:
    """Collapse identical CVEs reported across multiple OS binary sub-packages (e.g. util-linux)."""
    grouped: Dict[Tuple[str, str, Optional[str]], List[VulnerabilityFinding]] = {}
    order: List[Tuple[str, str, Optional[str]]] = []
    for f in findings:
        key = (f.id, f.version, f.fixed_by)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(f)

    collapsed: List[VulnerabilityFinding] = []
    for key in order:
        items = grouped[key]
        first = items[0]
        if len(items) == 1:
            collapsed.append(first)
        else:
            unique_pkgs = list(dict.fromkeys(x.package for x in items if x.package))
            pkg_label = (
                f"{unique_pkgs[0]} (+{len(unique_pkgs) - 1} pkgs)"
                if len(unique_pkgs) > 1
                else first.package
            )
            collapsed.append(
                VulnerabilityFinding(
                    id=first.id,
                    severity=first.severity,
                    cvss=first.cvss,
                    package=pkg_label,
                    version=first.version,
                    fixed_by=first.fixed_by,
                    title=first.title,
                    source=first.source,
                    aliases=list(first.aliases),
                )
            )
    return collapsed


def _compute_upgrade_rollup(
    findings: List[VulnerabilityFinding],
) -> List[Tuple[str, str, str, Dict[str, int]]]:
    """Group fixable findings by (package, version) and compute the minimal required upgrade version."""
    by_pkg: Dict[Tuple[str, str], List[VulnerabilityFinding]] = {}
    for f in findings:
        if not f.fixed_by or not f.package:
            continue
        key = (f.package, f.version)
        by_pkg.setdefault(key, []).append(f)

    rollups: List[Tuple[str, str, str, Dict[str, int]]] = []
    for (pkg, ver), pkg_findings in by_pkg.items():
        target_fix = pick_highest_fix_version(
            [f.fixed_by for f in pkg_findings if f.fixed_by],
            current_version=ver,
        )
        counts = _severity_counts(pkg_findings)
        rollups.append((pkg, ver, target_fix, counts))

    rollups.sort(
        key=lambda r: (
            -r[3]["CRITICAL"],
            -r[3]["HIGH"],
            -r[3]["MEDIUM"],
            r[0],
        )
    )
    return rollups


def _truncate_cell(val: str, max_width: int) -> str:
    if len(val) <= max_width:
        return val
    return val[: max_width - 1] + "…"


def run_scan(
    image_refs: List[str],
    lockfile_paths: List[str],
    pkg_specs: List[str],
    min_severity: str = "low",
    fixable_only: bool = False,
    direct_only: bool = False,
    trigger_harbor_scan: bool = True,
    scan_timeout: int = 60,
    platform: str = "linux/amd64",
    quiet: bool = False,
    warnings_out: Optional[List[str]] = None,
    allow_local_trivy: bool = True,
) -> Tuple[List[ImageScanResult], List[PackageScanResult]]:
    parse_warnings: List[str] = []
    builtin_lockfiles: List[str] = []
    trivy_fs_targets: List[str] = []
    has_local_trivy = allow_local_trivy and bool(shutil.which("trivy"))

    for lf in lockfile_paths:
        if has_local_trivy and is_trivy_fs_target(lf):
            trivy_fs_targets.append(lf)
        else:
            builtin_lockfiles.append(lf)

    images, packages = resolve_explicit_targets(
        image_refs,
        builtin_lockfiles,
        pkg_specs,
        warnings=parse_warnings,
    )
    if warnings_out is not None:
        warnings_out.extend(parse_warnings)
    if not quiet:
        for w in parse_warnings:
            print(f"[regscout] warning: {w}", file=sys.stderr)

    min_sev_rank = SEVERITY_ORDER.get(min_severity.upper(), 1)

    if direct_only:
        packages = [p for p in packages if p.direct]

    image_results: List[ImageScanResult] = []

    for img in images:
        res = ImageScanResult(
            image=img.raw,
            registry=img.registry,
            repository=img.repository,
            tag=img.tag,
            digest=img.digest,
        )

        # Step 1: Native Registry Scanners (Quay Clair, Docker Scout, Harbor v2 Trivy)
        registry_scanned = False
        if img.registry == "quay.io":
            registry_scanned = scan_quay_image(img, res, platform=platform)
        elif img.registry == "docker.io":
            registry_scanned = scan_docker_scout_image(img, res, platform=platform)
        elif img.registry in ("ghcr.io", "gcr.io", "k8s.gcr.io", "registry.k8s.io"):
            registry_scanned = False
        else:
            registry_scanned = scan_harbor_image(
                img,
                res,
                trigger_if_unscanned=trigger_harbor_scan,
                scan_timeout=scan_timeout,
                quiet=quiet,
            )

        # Step 2: Zero-Pull OCI SBOM Attestation + OSV.dev (if registry had no native scan)
        if not registry_scanned and res.status not in ("auth_required", "not_found"):
            registry_scanned = scan_oci_sbom_attestation(img, res, platform=platform)

        # Step 3: Local Trivy CLI Fallback (`trivy image`) when no registry scan or OCI SBOM exists
        if not registry_scanned and res.status not in ("auth_required", "not_found"):
            registry_scanned = scan_local_trivy_image(
                img,
                res,
                platform=platform,
                scan_timeout=max(scan_timeout, 300),
                quiet=quiet,
                allow_local_trivy=allow_local_trivy,
            )

        if not res.scanners_used and res.status == "ok":
            res.status = "unscanned"
            if not res.notes:
                res.notes.append(
                    "No native registry scan or OCI SBOM attestation found (install `trivy` via `brew install trivy` to scan unindexed images)"
                )

        res.findings = _filter_findings(res.findings, min_sev_rank, fixable_only)
        image_results.append(res)

    all_specs: List[Tuple[str, str, str]] = [
        (p.ecosystem, p.name, p.version) for p in packages
    ]

    pkg_map_results, batch_errors = query_packages_multi_source(all_specs)

    pkg_results: List[PackageScanResult] = []
    for p in packages:
        spec = (p.ecosystem, p.name, p.version)
        raw_findings = pkg_map_results.get(spec, [])
        filtered = _filter_findings(raw_findings, min_sev_rank, fixable_only)
        pkg_status = "error" if batch_errors else "ok"
        pkg_notes = list(batch_errors) if batch_errors else []
        pkg_results.append(
            PackageScanResult(
                ecosystem=p.ecosystem,
                name=p.name,
                version=p.version,
                source=p.source,
                direct=p.direct,
                status=pkg_status,
                notes=pkg_notes,
                findings=filtered,
            )
        )

    for target_path in trivy_fs_targets:
        fs_pkgs, fs_warnings = scan_local_trivy_fs(
            target_path,
            scan_timeout=max(scan_timeout, 180),
            quiet=quiet,
        )
        if warnings_out is not None:
            warnings_out.extend(fs_warnings)
        if not quiet:
            for w in fs_warnings:
                print(f"[regscout] warning: {w}", file=sys.stderr)
        for pr in fs_pkgs:
            if direct_only and not pr.direct:
                continue
            pr.findings = _filter_findings(pr.findings, min_sev_rank, fixable_only)
            pkg_results.append(pr)

    return image_results, pkg_results


def format_json_report(
    image_results: List[ImageScanResult],
    pkg_results: List[PackageScanResult],
    warnings: Optional[List[str]] = None,
) -> str:
    all_findings: List[VulnerabilityFinding] = []
    errors: List[str] = []
    for ir in image_results:
        all_findings.extend(ir.findings)
        if ir.status != "ok":
            errors.append(
                f"image {ir.image}: status={ir.status}"
                + (f" ({'; '.join(ir.notes)})" if ir.notes else "")
            )
    for pr in pkg_results:
        all_findings.extend(pr.findings)
        if pr.status != "ok":
            errors.append(
                f"package {pr.ecosystem}:{pr.name}@{pr.version}: status={pr.status}"
                + (f" ({'; '.join(pr.notes)})" if pr.notes else "")
            )

    summary = _severity_counts(all_findings)
    fixable_count = sum(1 for f in all_findings if f.fixed_by)
    incomplete_images = sum(1 for ir in image_results if ir.status != "ok")
    incomplete_packages = sum(1 for pr in pkg_results if pr.status != "ok")

    payload: Dict[str, Any] = {
        "tool": "regscout",
        "version": __version__,
        "summary": {
            "images_scanned": len(image_results),
            "incomplete_images": incomplete_images,
            "packages_scanned": len(pkg_results),
            "incomplete_packages": incomplete_packages,
            "total_findings": len(all_findings),
            "fixable_findings": fixable_count,
            "by_severity": summary,
            "errors": errors,
            "warnings": list(warnings or []),
        },
        "images": [dataclasses.asdict(ir) for ir in image_results],
        "vulnerable_packages": [
            dataclasses.asdict(pr) for pr in pkg_results if pr.findings or pr.status != "ok"
        ],
    }
    return json.dumps(payload, indent=2)


def _format_sev_badges(counts: Dict[str, int], st: _Styler) -> str:
    parts: List[str] = []
    if counts["CRITICAL"]:
        parts.append(st.red_bold(f"{counts['CRITICAL']} CRITICAL"))
    if counts["HIGH"]:
        parts.append(st.yellow(f"{counts['HIGH']} HIGH"))
    if counts["MEDIUM"]:
        parts.append(st.cyan(f"{counts['MEDIUM']} MEDIUM"))
    if counts["LOW"]:
        parts.append(st.dim(f"{counts['LOW']} LOW"))
    return ", ".join(parts) if parts else st.green("0 vulnerabilities")


def _render_findings_table(
    findings: List[VulnerabilityFinding],
    st: _Styler,
    max_rows: int = 10,
) -> List[str]:
    rows: List[str] = []
    collapsed = _collapse_subpackage_findings(findings)
    shown = collapsed[:max_rows]
    if not shown:
        return rows

    id_w = max(14, min(24, max(len(f.id.split()[0]) for f in shown)))
    pkg_w = max(12, min(26, max(len(f.package or "-") for f in shown)))
    ver_cells = []
    for f in shown:
        v_raw = f.version or "-"
        fix_raw = _truncate_cell(f.fixed_by, 14) if f.fixed_by else "no fix"
        ver_cells.append((v_raw, fix_raw, len(v_raw) + 4 + len(fix_raw)))
    ver_w = max(16, min(30, max(c[2] for c in ver_cells)))

    header = (
        f"    {'SEV'.ljust(8)}  {'CVSS'.rjust(4)}  {'ID'.ljust(id_w)}  "
        f"{'PACKAGE'.ljust(pkg_w)}  {'VERSION -> FIX'.ljust(ver_w)}  SUMMARY"
    )
    rows.append(st.dim(header))

    for f, (v_raw, fix_raw, _vw) in zip(shown, ver_cells):
        sev_col = st.severity(f.severity, width=8)
        cvss_raw = f"{f.cvss:4.1f}" if f.cvss is not None and f.cvss > 0 else "   -"
        cvss_col = st.bold(cvss_raw) if (f.cvss or 0) >= 9.0 else st.dim(cvss_raw)

        short_id = _truncate_cell(f.id.split()[0], id_w).ljust(id_w)
        pkg_cell = _truncate_cell(f.package or "-", pkg_w).ljust(pkg_w)

        plain_ver_pair = f"{_truncate_cell(v_raw, 13)} -> {fix_raw}"
        pad_needed = max(0, ver_w - len(plain_ver_pair))
        if f.fixed_by:
            ver_col = (
                f"{_truncate_cell(v_raw, 13)} {st.dim('->')} "
                f"{st.green(fix_raw)}{' ' * pad_needed}"
            )
        else:
            ver_col = st.dim(plain_ver_pair.ljust(ver_w))

        summary_col = clean_description(f.title, max_len=58)
        rows.append(
            f"    {sev_col}  {cvss_col}  {short_id}  {st.cyan(pkg_cell)}  {ver_col}  {summary_col}"
        )

    hidden_collapsed = len(collapsed) - len(shown)
    hidden_subpkgs = len(findings) - len(collapsed)
    footer_notes: List[str] = []
    if hidden_collapsed > 0:
        footer_notes.append(f"+{hidden_collapsed} more CVEs")
    if hidden_subpkgs > 0:
        footer_notes.append(f"{hidden_subpkgs} duplicate OS sub-package entries collapsed")
    if footer_notes:
        rows.append(
            st.dim(f"    … {', '.join(footer_notes)} (use `--format json` for full raw output)")
        )
    return rows


def format_text_report(
    image_results: List[ImageScanResult],
    pkg_results: List[PackageScanResult],
    color: bool = False,
) -> str:
    st = _Styler(enabled=color)
    lines: List[str] = []
    lines.append(
        st.bold(f"regscout v{__version__}")
        + st.dim(" — Zero-Pull Container & Package CVE Report")
    )
    lines.append("")

    if image_results:
        lines.append(st.bold(f"CONTAINER IMAGES ({len(image_results)} scanned)"))
        lines.append(st.dim("─" * 96))
        for ir in image_results:
            counts = _severity_counts(ir.findings)
            fixable = [f for f in ir.findings if f.fixed_by]
            scanners = ", ".join(ir.scanners_used) if ir.scanners_used else ir.status
            if ir.scan_triggered:
                scanners += " (triggered live scan)"

            if ir.status != "ok":
                status_icon = st.yellow("⚠")
            elif not ir.findings:
                status_icon = st.green_bold("✓")
            elif counts["CRITICAL"]:
                status_icon = st.red_bold("✗")
            else:
                status_icon = st.yellow("!")

            lines.append(f"{status_icon} {st.bold(ir.image)}  {st.dim(f'[{scanners}]')}")
            if ir.upstream_repo:
                lines.append(f"  {st.dim('Upstream :')} {ir.upstream_repo}")
            for note in ir.notes:
                lines.append(f"  {st.yellow('Note     :')} {note}")

            if not ir.findings:
                if ir.status == "ok":
                    lines.append(
                        f"  {st.dim('Status   :')} {st.green('Clean (0 matching vulnerabilities)')}"
                    )
                else:
                    lines.append(
                        f"  {st.dim('Status   :')} "
                        f"{st.yellow(f'Scan incomplete ({ir.status}) — cannot verify clean')}"
                    )
                lines.append("")
                continue

            fix_badge = (
                st.green(f"{len(fixable)} fixable")
                if fixable
                else st.dim("0 fixable (no upstream fix yet)")
            )
            lines.append(
                f"  {st.dim('Summary  :')} {len(ir.findings)} total ({fix_badge}) — "
                f"{_format_sev_badges(counts, st)}"
            )

            rollups = _compute_upgrade_rollup(ir.findings)
            if rollups:
                lines.append(f"  {st.bold('Recommended Upgrades:')}")
                for pkg, cur_ver, target_fix, r_counts in rollups[:6]:
                    sev_str = _format_sev_badges(r_counts, st)
                    lines.append(
                        f"    • {st.cyan(pkg.ljust(26))} {cur_ver} {st.dim('->')} "
                        f"{st.green_bold(target_fix)}  ({sev_str})"
                    )
                if len(rollups) > 6:
                    lines.append(st.dim(f"    • … +{len(rollups) - 6} more packages with fixes"))

            target_list = fixable if fixable else ir.findings
            table_title = "Fixable Findings:" if fixable else "Top Findings (unfixable upstream):"
            lines.append(f"  {st.bold(table_title)}")
            lines.extend(_render_findings_table(target_list, st, max_rows=8))
            lines.append("")

    if pkg_results:
        vuln_pkgs = [p for p in pkg_results if p.findings]
        err_pkgs = [p for p in pkg_results if p.status != "ok"]
        lines.append(
            st.bold(
                f"PACKAGES & LOCKFILES via OSV.dev + cve.now ({len(pkg_results)} checked, {len(vuln_pkgs)} vulnerable)"
            )
        )
        lines.append(st.dim("─" * 96))
        if err_pkgs:
            lines.append(
                f"  {st.yellow('⚠')} {st.yellow(f'{len(err_pkgs)} package check(s) failed ({err_pkgs[0].notes[0] if err_pkgs[0].notes else err_pkgs[0].status}) — cannot verify clean')}"
            )
            lines.append("")
        elif not vuln_pkgs:
            lines.append(f"  {st.green_bold('✓')} {st.green('0 vulnerable packages found.')}")
            lines.append("")
        for pr in vuln_pkgs:
            counts = _severity_counts(pr.findings)
            dep_kind = "direct" if pr.direct else "indirect"
            target_fix = pick_highest_fix_version(
                [f.fixed_by for f in pr.findings if f.fixed_by],
                current_version=pr.version,
            )
            upgrade_hint = (
                f"  {st.dim('-> upgrade to')} {st.green_bold(target_fix)}"
                if target_fix != "unknown"
                else ""
            )
            icon = st.red_bold("✗") if counts["CRITICAL"] else st.yellow("!")
            lines.append(
                f"{icon} {st.bold(f'{pr.ecosystem}:{pr.name}@{pr.version}')}{upgrade_hint} "
                f"{st.dim(f'({dep_kind}, {pr.source})')}"
            )
            lines.extend(_render_findings_table(pr.findings, st, max_rows=6))
            lines.append("")

    return "\n".join(lines)


def format_markdown_report(
    image_results: List[ImageScanResult],
    pkg_results: List[PackageScanResult],
) -> str:
    lines: List[str] = []
    lines.append("# `regscout` Vulnerability Report")
    lines.append("")
    if image_results:
        lines.append("## Container Images")
        lines.append("")
        lines.append("| Image | Status | Scanner(s) | Critical | High | Medium | Low | Fixable |")
        lines.append("| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: |")
        for ir in image_results:
            c = _severity_counts(ir.findings)
            fixable = sum(1 for f in ir.findings if f.fixed_by)
            scanners = ", ".join(f"`{s}`" for s in ir.scanners_used) or "-"
            lines.append(
                f"| `{ir.image}` | `{ir.status}` | {scanners} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | {fixable} |"
            )
        lines.append("")

    if pkg_results:
        vuln_pkgs = [p for p in pkg_results if p.findings]
        lines.append(
            f"## Packages & Lockfiles (`OSV.dev` + `cve.now` — {len(vuln_pkgs)} of {len(pkg_results)} vulnerable)"
        )
        lines.append("")
        if not vuln_pkgs:
            lines.append("No package vulnerabilities matched.")
        else:
            lines.append("| Package | Source | Direct | Top Findings |")
            lines.append("| :--- | :--- | :---: | :--- |")
            for pr in vuln_pkgs:
                top = "; ".join(
                    f"**{f.id}** ({f.severity}, fix: `{f.fixed_by or 'n/a'}`)"
                    for f in pr.findings[:3]
                )
                if len(pr.findings) > 3:
                    top += f" (+{len(pr.findings) - 3} more)"
                lines.append(
                    f"| `{pr.ecosystem}:{pr.name}@{pr.version}` | `{pr.source}` | {'Yes' if pr.direct else 'No'} | {top} |"
                )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="regscout",
        description=(
            "Zero-pull container & package CVE scanner. Pass container images (--image or positional), "
            "lockfiles (--lockfile), and/or packages (--pkg) in any combination."
        ),
    )
    parser.add_argument(
        "images",
        nargs="*",
        default=[],
        help="Container image reference(s) to scan (e.g. postgres:16 quay.io/prometheus/prometheus:v2.55.1).",
    )
    parser.add_argument(
        "-i",
        "--image",
        action="append",
        default=[],
        help="Container image reference to scan (repeatable).",
    )
    parser.add_argument(
        "-l",
        "--lockfile",
        action="append",
        default=[],
        help=(
            "Path to a dependency lockfile or directory to scan "
            "(go.mod, requirements.txt, uv.lock, poetry.lock, package-lock.json, Cargo.lock; "
            "or directory / third-party lockfile via local Trivy if installed)."
        ),
    )
    parser.add_argument(
        "-p",
        "--pkg",
        action="append",
        default=[],
        help="Package spec to scan in <eco>:<name>@<version> format (repeatable or comma-separated, e.g. pypi:pyjwt@2.10).",
    )
    parser.add_argument(
        "--platform",
        default="linux/amd64",
        help="Target container platform for multi-arch manifests and SBOMs (default: linux/amd64).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text; use 'json' for coding agents and automation).",
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize terminal text output (default: auto; respects NO_COLOR).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output (alias for --color never).",
    )
    parser.add_argument(
        "--min-severity",
        choices=["unknown", "low", "medium", "high", "critical"],
        default="low",
        help="Minimum vulnerability severity to include (default: low).",
    )
    parser.add_argument(
        "--fixable-only",
        action="store_true",
        help="Only include vulnerabilities that have an upstream fix version available.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only check direct dependencies in lockfiles.",
    )
    parser.add_argument(
        "--no-trigger-scan",
        action="store_true",
        help="Do not trigger a new server-side Trivy scan on Harbor if an artifact is unscanned.",
    )
    parser.add_argument(
        "--no-local-trivy",
        action="store_true",
        help="Do not fall back to local 'trivy' CLI when an image lacks a registry scan and OCI SBOM.",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=60,
        help="Max seconds to wait for a triggered Harbor Trivy scan to finish (default: 60).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: none).",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit with code 3 if any target fails to scan or is unscanned.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress and warning messages on stderr.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    all_images = list(args.images) + list(args.image)
    if not all_images and not args.lockfile and not args.pkg:
        parser.print_help(sys.stderr)
        return 2

    scan_warnings: List[str] = []
    try:
        image_results, pkg_results = run_scan(
            image_refs=all_images,
            lockfile_paths=args.lockfile,
            pkg_specs=args.pkg,
            min_severity=args.min_severity,
            fixable_only=args.fixable_only,
            direct_only=args.direct_only,
            trigger_harbor_scan=not args.no_trigger_scan,
            scan_timeout=args.scan_timeout,
            platform=args.platform,
            quiet=args.quiet or (args.format == "json"),
            warnings_out=scan_warnings,
            allow_local_trivy=not args.no_local_trivy,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color_mode = "never" if args.no_color else args.color
    if args.format == "json":
        print(format_json_report(image_results, pkg_results, warnings=scan_warnings))
    elif args.format == "markdown":
        print(format_markdown_report(image_results, pkg_results))
    else:
        print(
            format_text_report(
                image_results,
                pkg_results,
                color=_should_use_color(color_mode),
            )
        )

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        for ir in image_results:
            if any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= threshold for f in ir.findings):
                return 1
        for pr in pkg_results:
            if any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= threshold for f in pr.findings):
                return 1

    if args.fail_on_error or args.fail_on != "none":
        if any(ir.status != "ok" for ir in image_results) or any(
            pr.status != "ok" for pr in pkg_results
        ):
            return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
