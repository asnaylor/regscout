"""Offline unit test suite for regscout covering all 7 review bugs and OSV/SBOM features."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from regscout.auth import _hosts_equivalent, _normalize_host, resolve_registry_auth
from regscout.cli import (
    format_json_report,
    format_text_report,
    main,
)
from regscout.discovery import (
     parse_image_ref,
    parse_lockfile,
)
from regscout.scanners import (
    ImageScanResult,
    PackageScanResult,
    VulnerabilityFinding,
    _cmp_semver,
    _parse_osv_vuln_detail,
    _version_matches_cvenow_affected,
    compute_cvss_v3_base_score,
    extract_purls_from_sbom,
    merge_findings,
    pick_highest_fix_version,
    query_cve_now_batch,
    scan_local_trivy_fs,
    scan_local_trivy_image,
)


class TestBug1SilentFalseNegatives(unittest.TestCase):
    """Bug #1: Failed/errored scans must never report clean or exit 0 under --fail-on-error."""

    def test_failed_image_scan_renders_warning_and_incomplete_json(self) -> None:
        img = ImageScanResult(
            image="ghcr.io/example/private-app:1.0.0",
            registry="ghcr.io",
            repository="example/private-app",
            tag="1.0.0",
            digest=None,
            status="auth_required",
            notes=["HTTP 401 Unauthorized fetching manifest"],
        )
        pkg = PackageScanResult(
            ecosystem="pypi",
            name="requests",
            version="2.31.0",
            source="--pkg",
            direct=True,
            status="error",
            notes=["OSV.dev query failed: timeout", "cve.now query failed: timeout"],
        )

        text_out = format_text_report([img], [pkg], color=False)
        self.assertIn("Scan incomplete (auth_required) — cannot verify clean", text_out)
        self.assertIn("package check(s) failed (OSV.dev query failed: timeout) — cannot verify clean", text_out)
        self.assertNotIn("Clean (0 matching vulnerabilities)", text_out)
        self.assertNotIn("0 vulnerable packages found.", text_out)

        json_out = json.loads(format_json_report([img], [pkg], warnings=["sample warning"]))
        self.assertEqual(json_out["summary"]["incomplete_images"], 1)
        self.assertEqual(json_out["summary"]["incomplete_packages"], 1)
        self.assertEqual(len(json_out["summary"]["errors"]), 2)
        self.assertEqual(json_out["summary"]["warnings"], ["sample warning"])

    def test_cli_exit_code_3_on_incomplete_scan_with_fail_on(self) -> None:
        failed_img = ImageScanResult(
            image="ghcr.io/example/private-app:1.0.0",
            registry="ghcr.io",
            repository="example/private-app",
            tag="1.0.0",
            digest=None,
            status="unscanned",
            notes=["Could not authenticate"],
        )
        with mock.patch("regscout.cli.run_scan", return_value=([failed_img], [])):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                code_default = main(["ghcr.io/example/private-app:1.0.0"])
                self.assertEqual(code_default, 0)

                code_fail_on_err = main(["--fail-on-error", "ghcr.io/example/private-app:1.0.0"])
                self.assertEqual(code_fail_on_err, 3)

                code_fail_on_sev = main(["--fail-on", "high", "ghcr.io/example/private-app:1.0.0"])
                self.assertEqual(code_fail_on_sev, 3)


class TestBug2CveNowBatchCrossContamination(unittest.TestCase):
    """Bug #2: cve.now batch queries must not attach CVEs from an older version to a newer version."""

    def test_batch_distinguishes_same_package_different_versions(self) -> None:
        specs = [
            ("pypi", "flask", "3.1.0"),
            ("pypi", "flask", "2.2.2"),
        ]

        mock_api_response = {
            "entries": [
                {
                    "id": "CVE-2023-30861",
                    "title": "CVE-2023-30861: Flask session cookie disclosure",
                    "statedSeverity": "HIGH",
                    "severity": {"cvss": 7.5},
                    "matched": {"ecosystem": "pypi", "package": "flask", "version": "2.2.2"},
                    "affected": [
                        {
                            "package": "flask",
                            "ecosystem": "pypi",
                            "ranges": [{"introduced": "0", "fixed": "2.2.5"}],
                            "fixed": ["2.2.5", "2.3.2"],
                        }
                    ],
                }
            ]
        }

        with mock.patch("regscout.scanners._http_json", return_value=mock_api_response):
            results, errs = query_cve_now_batch(specs)

        self.assertEqual(errs, [])
        self.assertEqual(results[("pypi", "flask", "3.1.0")], [])
        self.assertEqual(len(results[("pypi", "flask", "2.2.2")]), 1)
        self.assertEqual(results[("pypi", "flask", "2.2.2")][0].id, "CVE-2023-30861")
        self.assertEqual(results[("pypi", "flask", "2.2.2")][0].fixed_by, "2.2.5, 2.3.2")

    def test_version_matches_cvenow_affected(self) -> None:
        aff = {
            "package": "urllib3",
            "ecosystem": "pypi",
            "ranges": [
                {"introduced": "1.25.0", "fixed": "1.26.18"},
                {"introduced": "2.0.0", "fixed": "2.0.7"},
            ],
        }
        self.assertTrue(_version_matches_cvenow_affected("1.26.5", aff))
        self.assertFalse(_version_matches_cvenow_affected("1.26.18", aff))
        self.assertFalse(_version_matches_cvenow_affected("2.2.1", aff))


class TestBug3StrictLockfileDispatch(unittest.TestCase):
    """Bug #3: Unsupported lockfile formats must raise ValueError instead of falling back to requirements.txt."""

    def test_unsupported_lockfiles_raise_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for bad_name in ("yarn.lock", "pnpm-lock.yaml", "random.json", "foo.mod"):
                p = Path(tmp) / bad_name
                p.write_text("somepkg==1.0.0\n", encoding="utf-8")
                with self.assertRaises(ValueError, msg=f"Expected ValueError for {bad_name}"):
                    parse_lockfile(str(p))

    def test_supported_requirements_filenames_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for good_name in ("requirements.txt", "requirements-dev.txt", "dev.requirements.txt", "constraints.txt"):
                p = Path(tmp) / good_name
                p.write_text("requests==2.31.0\n", encoding="utf-8")
                warnings: list[str] = []
                deps = parse_lockfile(str(p), warnings=warnings)
                self.assertEqual(len(deps), 1)
                self.assertEqual(deps[0].name, "requests")
                self.assertEqual(deps[0].version, "2.31.0")
                self.assertEqual(warnings, [])


class TestBug4RequirementsRangePins(unittest.TestCase):
    """Bug #4: Non-exact version ranges in requirements.txt must be skipped with a warning."""

    def test_range_specifiers_emit_warning_and_only_exact_pins_are_returned(self) -> None:
        content = """
        requests==2.31.0
        urllib3>=1.26.0,<3.0.0
        flask~=2.3.0
        werkzeug===3.0.1
        unpinned-pkg
        """
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text(content, encoding="utf-8")
            warnings: list[str] = []
            deps = parse_lockfile(str(req), warnings=warnings)

        self.assertEqual([(d.name, d.version) for d in deps], [("requests", "2.31.0"), ("werkzeug", "3.0.1")])
        self.assertEqual(len(warnings), 3)
        self.assertTrue(any("urllib3>=1.26.0" in w for w in warnings))
        self.assertTrue(any("flask~=2.3.0" in w for w in warnings))
        self.assertTrue(any("unpinned-pkg" in w for w in warnings))


class TestBug5PickHighestFixVersion(unittest.TestCase):
    """Bug #5: pick_highest_fix_version must choose the minimal fix per CVE for the installed branch."""

    def test_single_cve_multi_branch_picks_same_branch_fix(self) -> None:
        # CVE fixed in 1.26.18 (1.x branch) and 2.0.7 (2.x branch)
        fix = pick_highest_fix_version(["1.26.18, 2.0.7"], current_version="1.26.5")
        self.assertEqual(fix, "1.26.18")

    def test_multiple_cves_picks_max_of_minimal_branch_fixes(self) -> None:
        # CVE-1 fixed in 1.26.15 or 2.0.5; CVE-2 fixed in 1.26.18 or 2.0.7
        fix = pick_highest_fix_version(
            ["1.26.15, 2.0.5", "1.26.18, 2.0.7"],
            current_version="1.26.5",
        )
        self.assertEqual(fix, "1.26.18")


class TestBug6NoBlindRepoGuessingAndLocalTrivyFallback(unittest.TestCase):
    """Bug #6: Never mark an unindexed image clean via GitHub repo guessing; fall back to local Trivy or mark unscanned."""

    def test_unindexed_image_without_local_trivy_reports_unscanned(self) -> None:
        ref = parse_image_ref("ghcr.io/berriai/litellm:v1.103.2")
        assert ref is not None
        res = ImageScanResult(
            image=ref.raw,
            registry=ref.registry,
            repository=ref.repository,
            tag=ref.tag,
            digest=ref.digest,
        )
        with mock.patch("regscout.scanners.shutil.which", return_value=None):
            ok = scan_local_trivy_image(ref, res, quiet=True)
        self.assertFalse(ok)
        self.assertEqual(res.status, "unscanned")
        self.assertEqual(res.scanners_used, [])
        self.assertTrue(any("brew install trivy" in n for n in res.notes))

    def test_unindexed_image_with_local_trivy_scans_os_and_lang_packages(self) -> None:
        ref = parse_image_ref("ghcr.io/berriai/litellm:v1.103.2")
        assert ref is not None
        res = ImageScanResult(
            image=ref.raw,
            registry=ref.registry,
            repository=ref.repository,
            tag=ref.tag,
            digest=ref.digest,
        )
        mock_trivy_json = json.dumps(
            {
                "Metadata": {
                    "RepoDigests": [
                        "ghcr.io/berriai/litellm@sha256:6b215d3eb4693622bd81ca68049a16f71099e772409f44d38da66ad9f73774a0"
                    ]
                },
                "Results": [
                    {
                        "Target": "ghcr.io/berriai/litellm:v1.103.2 (wolfi 20230201)",
                        "Class": "os-pkgs",
                        "Type": "wolfi",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-111497",
                                "PkgName": "libbrotlidec1",
                                "InstalledVersion": "1.2.0-r5",
                                "FixedVersion": "1.2.0-r7",
                                "Severity": "HIGH",
                                "Title": "Out-of-Bounds Write in Brotli Decoder (Node2Shell)",
                                "CVSS": {"nvd": {"V3Score": 9.2}},
                            }
                        ],
                    }
                ],
            }
        )
        fake_proc = mock.Mock(returncode=0, stdout=mock_trivy_json, stderr="")
        with mock.patch("regscout.scanners.shutil.which", return_value="/opt/homebrew/bin/trivy"):
            with mock.patch("regscout.scanners.subprocess.run", return_value=fake_proc):
                ok = scan_local_trivy_image(ref, res, quiet=True)
        self.assertTrue(ok)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.scanners_used, ["trivy-local"])
        self.assertEqual(
            res.digest,
            "sha256:6b215d3eb4693622bd81ca68049a16f71099e772409f44d38da66ad9f73774a0",
        )
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].id, "CVE-2026-111497")
        self.assertEqual(res.findings[0].package, "libbrotlidec1")
        self.assertEqual(res.findings[0].fixed_by, "1.2.0-r7")
        self.assertEqual(res.findings[0].cvss, 9.2)

    def test_scan_local_trivy_fs_parses_packages_and_vulns(self) -> None:
        mock_trivy_fs_json = json.dumps(
            {
                "Results": [
                    {
                        "Target": "yarn.lock",
                        "Class": "lang-pkgs",
                        "Type": "yarn",
                        "Packages": [
                            {
                                "Name": "lodash",
                                "Version": "4.17.20",
                                "Relationship": "direct",
                            }
                        ],
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2021-23337",
                                "PkgName": "lodash",
                                "InstalledVersion": "4.17.20",
                                "FixedVersion": "4.17.21",
                                "Severity": "HIGH",
                                "Title": "Command Injection in lodash",
                                "CVSS": {"ghsa": {"V3Score": 7.2}},
                            }
                        ],
                    }
                ]
            }
        )
        fake_proc = mock.Mock(returncode=0, stdout=mock_trivy_fs_json, stderr="")
        with mock.patch("regscout.scanners.shutil.which", return_value="/opt/homebrew/bin/trivy"):
            with mock.patch("regscout.scanners.subprocess.run", return_value=fake_proc):
                pkgs, warnings = scan_local_trivy_fs("yarn.lock", quiet=True)
        self.assertEqual(warnings, [])
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0].ecosystem, "npm")
        self.assertEqual(pkgs[0].name, "lodash")
        self.assertEqual(pkgs[0].version, "4.17.20")
        self.assertEqual(len(pkgs[0].findings), 1)
        self.assertEqual(pkgs[0].findings[0].id, "CVE-2021-23337")


class TestBug7AuthLockfilesGoModSemver(unittest.TestCase):
    """Bug #7a-d: Docker Hub alias matching, tomllib lockfiles, go.mod replace/stdlib, and pre-release semver."""

    def test_bug7a_docker_hub_host_aliases(self) -> None:
        self.assertEqual(_normalize_host("https://index.docker.io/v1/"), "docker.io")
        self.assertEqual(_normalize_host("registry-1.docker.io"), "docker.io")
        self.assertTrue(_hosts_equivalent("index.docker.io", "registry-1.docker.io"))

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "auth.json"
            cfg.write_text(
                json.dumps(
                    {
                        "auths": {
                            "https://index.docker.io/v1/": {
                                # base64("testuser:testpass")
                                "auth": "dGVzdHVzZXI6dGVzdHBhc3M="
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"REGISTRY_AUTH_FILE": str(cfg)}):
                auth_header, source = resolve_registry_auth("registry-1.docker.io")
            self.assertEqual(auth_header, "Basic dGVzdHVzZXI6dGVzdHBhc3M=")
            self.assertEqual(source, "podman:$REGISTRY_AUTH_FILE")

    def test_bug7b_uv_cargo_and_npm_direct_vs_transitive(self) -> None:
        uv_content = """
version = 1

[[package]]
name = "my-workspace"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "fastapi" },
]

[[package]]
name = "fastapi"
version = "0.110.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "starlette" },
]

[[package]]
name = "starlette"
version = "0.36.3"
source = { registry = "https://pypi.org/simple" }
"""
        cargo_content = """
version = 3

[[package]]
name = "my-root-crate"
version = "0.1.0"
dependencies = [
    "serde 1.0.197",
]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
    "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
        npm_content = json.dumps(
            {
                "name": "my-web-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "my-web-app",
                        "dependencies": {"express": "^4.18.2"},
                    },
                    "node_modules/express": {"version": "4.18.2"},
                    "node_modules/body-parser": {"version": "1.20.1"},
                },
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            uv_path = Path(tmp) / "uv.lock"
            uv_path.write_text(uv_content, encoding="utf-8")
            uv_deps = {d.name: d for d in parse_lockfile(str(uv_path))}
            self.assertNotIn("my-workspace", uv_deps)
            self.assertTrue(uv_deps["fastapi"].direct)
            self.assertFalse(uv_deps["starlette"].direct)

            cargo_path = Path(tmp) / "Cargo.lock"
            cargo_path.write_text(cargo_content, encoding="utf-8")
            cargo_deps = {d.name: d for d in parse_lockfile(str(cargo_path))}
            self.assertNotIn("my-root-crate", cargo_deps)
            self.assertTrue(cargo_deps["serde"].direct)
            self.assertFalse(cargo_deps["serde_derive"].direct)

            npm_path = Path(tmp) / "package-lock.json"
            npm_path.write_text(npm_content, encoding="utf-8")
            npm_deps = {d.name: d for d in parse_lockfile(str(npm_path))}
            self.assertTrue(npm_deps["express"].direct)
            self.assertFalse(npm_deps["body-parser"].direct)

    def test_bug7c_go_mod_replace_and_stdlib_version(self) -> None:
        gomod_two_part = """
module example.com/my/service

go 1.22

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/internal/localpkg v0.0.0
)

replace (
    github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.1
    github.com/internal/localpkg => ../localpkg
)
"""
        gomod_with_toolchain = gomod_two_part + "\ntoolchain go1.22.4\n"

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "go.mod"
            p1.write_text(gomod_two_part, encoding="utf-8")
            deps1 = {d.name: d for d in parse_lockfile(str(p1))}
            # 2-part `go 1.22` should NOT emit a fake stdlib@1.22.0 dependency
            self.assertNotIn("stdlib", deps1)
            # local replace should be skipped
            self.assertNotIn("github.com/internal/localpkg", deps1)
            # version replace should substitute v1.9.1
            self.assertEqual(deps1["github.com/gin-gonic/gin"].version, "1.9.1")

            p2 = Path(tmp) / "go.mod"
            p2.write_text(gomod_with_toolchain, encoding="utf-8")
            deps2 = {d.name: d for d in parse_lockfile(str(p2))}
            self.assertIn("stdlib", deps2)
            self.assertEqual(deps2["stdlib"].version, "1.22.4")

    def test_bug7d_prerelease_semver_numeric_ordering(self) -> None:
        self.assertEqual(_cmp_semver("1.0.0-rc2", "1.0.0-rc10"), -1)
        self.assertEqual(_cmp_semver("1.0.0-rc10", "1.0.0"), -1)
        self.assertEqual(_cmp_semver("1.0.0", "1.0.0"), 0)


class TestOsvAndSbomPipeline(unittest.TestCase):
    """Tests for OCI SBOM PURL extraction, CVSS v3.1 vector scoring, and OSV + cve.now deduplication."""

    def test_extract_purls_from_in_toto_spdx_sbom(self) -> None:
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://spdx.dev/Document",
            "predicate": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "openssl",
                        "versionInfo": "3.1.4-r2",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:apk/alpine/openssl@3.1.4-r2?arch=x86_64",
                            }
                        ],
                    },
                    {
                        "name": "stdlib",
                        "versionInfo": "1.22.1",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:golang/stdlib@1.22.1",
                            }
                        ],
                    },
                ],
            },
        }
        purls = extract_purls_from_sbom(statement)
        self.assertEqual(
            purls,
            [
                ("pkg:apk/alpine/openssl@3.1.4-r2?arch=x86_64", "openssl", "3.1.4-r2"),
                ("pkg:golang/stdlib@1.22.1", "stdlib", "1.22.1"),
            ],
        )

    def test_compute_cvss_v3_base_score(self) -> None:
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 CRITICAL
        score = compute_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 HIGH
        score2 = compute_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(score2, 7.5)

    def test_merge_findings_deduplicates_ghsa_and_cve_via_aliases(self) -> None:
        osv_finding = VulnerabilityFinding(
            id="GHSA-j8r2-6x86-q33q",
            severity="MEDIUM",
            cvss=None,
            package="requests",
            version="2.28.1",
            fixed_by="2.31.0",
            title="Unintended leak of Proxy-Authorization header in requests",
            source="osv.dev",
            aliases=["CVE-2023-32681"],
        )
        cvenow_finding = VulnerabilityFinding(
            id="CVE-2023-32681",
            severity="MEDIUM",
            cvss=6.1,
            package="requests",
            version="2.28.1",
            fixed_by="2.31.0",
            title="Requests proxy auth leak",
            source="cve.now",
            aliases=["GHSA-j8r2-6x86-q33q"],
        )
        merged = merge_findings([osv_finding], [cvenow_finding])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].id, "CVE-2023-32681")
        self.assertEqual(merged[0].cvss, 6.1)
        self.assertEqual(merged[0].fixed_by, "2.31.0")

    def test_parse_osv_vuln_detail_promotes_upstream_cve_id(self) -> None:
        wolfi_doc = {
            "id": "CGA-xxxx-yyyy-zzzz",
            "upstream": ["CVE-2026-111497"],
            "summary": "Wolfi brotli security update",
            "affected": [
                {
                    "package": {"name": "brotli", "ecosystem": "Wolfi"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0-r7"}]}],
                }
            ],
        }
        finding = _parse_osv_vuln_detail(wolfi_doc, "brotli", "1.2.0-r5", source_label="oci-sbom-osv")
        self.assertEqual(finding.id, "CVE-2026-111497")
        self.assertIn("CGA-xxxx-yyyy-zzzz", finding.aliases)
        self.assertEqual(finding.fixed_by, "1.2.0-r7")


if __name__ == "__main__":
    unittest.main()
