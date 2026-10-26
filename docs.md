# regscout reference

Details behind the [README](README.md): output formats, exit codes, every option, how scanning works, and privacy.

- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Options](#options)
- [How it works](#how-it-works)
- [Privacy](#privacy)
- [Development](#development)

---

## Output formats

- `--format text` (default): colored report with per-package upgrade recommendations.
- `--format markdown`: tables for pasting into PRs and issues.
- `--format json`: for agents and automation. Shape (abridged):

```json
{
  "summary": {
    "images_scanned": 1, "incomplete_images": 0,
    "packages_scanned": 0, "incomplete_packages": 0,
    "total_findings": 4, "fixable_findings": 4,
    "by_severity": {"CRITICAL": 4, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
    "errors": [], "warnings": []
  },
  "images": [{
    "image": "postgres:16", "status": "ok", "scanners_used": ["docker-scout"],
    "findings": [{
      "id": "CVE-2025-68121", "severity": "CRITICAL", "cvss": 10.0,
      "package": "stdlib", "version": "1.24.6", "fixed_by": "1.24.13",
      "title": "...", "source": "docker-scout", "aliases": []
    }]
  }],
  "vulnerable_packages": []
}
```

The full field list and status values are in [`AGENTS.md`](AGENTS.md).

**A target that couldn't be scanned is never reported as clean.** Its `status` is one of `auth_required`, `not_found`, `unscanned`, or `error`, it counts toward `incomplete_*`, and the text report shows `⚠ Scan incomplete`.

---

## Exit codes

| Code | Meaning |
| :-: | :-- |
| `0` | Scan finished and nothing met `--fail-on`. |
| `1` | A finding met or exceeded `--fail-on <severity>` (takes precedence over `3`). |
| `2` | Usage error, missing lockfile, or unsupported lockfile type. |
| `3` | A target failed or was unscanned, and `--fail-on-error` or `--fail-on` was set. |

---

## Options

| Option | Description |
| :-- | :-- |
| `IMAGE...`, `-i/--image` | Image references to scan (repeatable). |
| `-l/--lockfile PATH` | Lockfile to scan (repeatable). See supported files below. |
| `-p/--pkg ECO:NAME@VER` | Package to scan (repeatable or comma-separated). Ecosystems: `pypi`, `go`, `npm`, `crates.io` (aliases: `pip`, `cargo`). |
| `--platform` | Platform for multi-arch images (default `linux/amd64`; use `linux/arm64` for Apple Silicon or Graviton targets). |
| `-f/--format` | `text`, `json`, or `markdown`. |
| `--min-severity` | `unknown`, `low` (default), `medium`, `high`, `critical`. |
| `--fixable-only` | Only findings with a known fix version. |
| `--direct-only` | Only direct dependencies in lockfiles. |
| `--fail-on` / `--fail-on-error` | Exit-code gates for CI (see above). |
| `--no-trigger-scan` | Don't ask Harbor to start a scan for an unscanned image. |
| `--scan-timeout` | Seconds to wait for a triggered Harbor scan (default 60). |
| `--no-local-trivy` | Never fall back to local `trivy`; mark such images `unscanned` instead. |
| `--color`, `--no-color`, `-q/--quiet` | Terminal output controls (`NO_COLOR` is respected). |

**Supported lockfiles:** `go.mod`, `requirements.txt` (only exact `==` pins are scanned; other lines produce a warning), `uv.lock`, `poetry.lock` (needs Python 3.11+), `package-lock.json`, `Cargo.lock`. With `trivy` installed, directories and `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `composer.lock`, `pom.xml` and similar are scanned via `trivy fs`. `--pkg` covers language packages only, not OS packages.

**Registry credentials** are read from Podman or Docker (`podman login` / `docker login`), including credential helpers. Secrets are never printed or logged.

---

## How it works

For each image, `regscout` tries these in order and reports which one answered in `scanners_used`:

1. **Native registry scan (no layers pulled).**
   - **Harbor v2** (e.g. `registry.nersc.gov`): reads the Trivy scan report through the Harbor API. If the image hasn't been scanned, it triggers a scan on the server and polls until it finishes (disable with `--no-trigger-scan`).
   - **Quay** (`quay.io`): reads Clair v4 results for your `--platform`.
   - **Docker Hub** (`docker.io`): reads Docker Scout results.
2. **OCI SBOM attestation (no layers pulled).** For registries without a scan API (`ghcr.io`, `gcr.io`, `registry.k8s.io`, generic OCI registries), it fetches the image's BuildKit/in-toto SBOM (SPDX or CycloneDX) and looks up every package on [OSV.dev](https://osv.dev).
3. **Local Trivy.** If neither exists and `trivy` is installed, `regscout` runs `trivy image`, then cross-checks the packages against OSV.dev. **This step downloads the image layers**, so it is slower and needs network access to the registry. Without `trivy` the image is reported `unscanned`.

Lockfiles and `--pkg` are checked against both OSV.dev and [cve.now](https://cve.now), merged and de-duplicated by CVE/GHSA alias. Upgrade recommendations pick, per CVE, the lowest fixed version on your release branch, then the highest of those across the package's CVEs.

---

## Privacy

Package names and versions from lockfiles and `--pkg` (including private module names) are sent to OSV.dev and cve.now. Image references go to the image's registry and, for Docker Hub, to Docker Scout. The optional local `trivy` fallback also contacts the registry and downloads Trivy's own vulnerability database.

---

## Development

```bash
python3 -B -m unittest discover -s tests -t . -v
```
