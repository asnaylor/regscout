# regscout

**Zero-pull container & dependency CVE scanner for humans and AI coding agents.**

`regscout` checks container images (`--image`), dependency lockfiles (`--lockfile`), and individual packages (`--pkg`) for known vulnerabilities **without pulling a single container layer locally** and **without noisy directory crawling**. You (or your AI agent) pass the exact images, lockfiles, or packages you want to check—either standalone or combined in one command.

---

## How the Pipeline Works

1. **Native Registry Scanners**
   - **Harbor v2 Registries (Trivy)** — e.g. NERSC Harbor (`registry.nersc.gov`). Verifies Harbor v2 via `/api/v2.0/systeminfo`, checks `scan_overview`, and **if the image has not been scanned yet, automatically triggers a remote Trivy scan (`POST .../scan`) and polls until the report completes**.
   - **Red Hat Quay (`quay.io` Clair v4)** — Resolves multi-arch manifest lists to `--platform` (default `linux/amd64`) and fetches OS + language layer findings.
   - **Docker Hub (`docker.io` Docker Scout GraphQL)** — Queries `api.dso.docker.com/v1/graphql` for indexed SBOM packages, CVEs, CVSS scores, and `fixedBy` versions.
2. **Zero-Pull OCI SBOM Attestation Scanner (`oci-sbom-osv`)** — When a registry has no native vulnerability API (such as `ghcr.io`, `gcr.io`, `registry.k8s.io`, or a generic OCI v2 registry), `regscout` inspects the OCI Image Index for BuildKit / in-toto SBOM attestations (`vnd.docker.reference.type: "attestation-manifest"` with SPDX or CycloneDX predicates), streams only the JSON SBOM blob, extracts every OS (`apk`, `deb`, `rpm`) and language (`pypi`, `golang`, `npm`, `cargo`) Package URL (`purl`), and batch-queries **[OSV.dev](https://osv.dev)** (`/v1/querybatch` + `/v1/vulns/<id>`).
3. **Verified OCI Source Label -> GitHub Security Advisories** — If an image has neither a native registry scanner nor an attached SBOM attestation, `regscout` reads verified OCI config/manifest source annotations (`org.opencontainers.image.source`), resolves the upstream GitHub `owner/repo`, queries GitHub Security Advisories, and cross-checks verified ecosystem package coordinates against `OSV.dev` and `cve.now`.
4. **Lockfiles (`--lockfile`) & Packages (`--pkg`) via `OSV.dev` + `cve.now`** — Parses `go.mod`, `requirements.txt`, `uv.lock`, `poetry.lock`, `package-lock.json`, or `Cargo.lock` (or individual `eco:name@version` specs) and queries both **Google OSV.dev** and **cve.now** in batches, deduplicating via CVE/GHSA aliases and calculating CVSS v3.1 base scores from vector strings when needed.

---

## Features

- **Zero external dependencies**: Pure Python 3.9+ standard library (`urllib.request`, `json`, `tomllib`, `argparse`).
- **Fail-safe error reporting**: Unscanned, unauthorized, or missing targets are flagged with `⚠ Scan incomplete` (and exit code `3` when `--fail-on-error` or `--fail-on` is set)—never silently reported as clean.
- **Smart branch-aware upgrade recommendations**: Recommends the minimal patched version on your installed release branch per CVE, then the highest required version across all CVEs for each package.
- **Podman & Docker credential support**: Automatically reads credentials from Podman (`$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`, `~/.config/containers/auth.json`) and Docker (`$DOCKER_CONFIG/config.json`, `~/.docker/config.json`), including `credHelpers` and `credsStore` and Docker Hub hostname aliases (`index.docker.io`, `registry-1.docker.io`, `docker.io`). Never prints or logs secret values.
- **Agent-ready**: Ships with [`AGENTS.md`](AGENTS.md), [`CLAUDE.md`](CLAUDE.md), and [`skills/regscout/SKILL.md`](skills/regscout/SKILL.md) for Claude Code, OpenAI Codex, Google Antigravity, and Cursor.

---

## Installation

```bash
# Install globally as a CLI tool with uv or pipx
uv tool install .
# or editable install
pip install -e .

# Or run directly without installing
python3 -m regscout --help
```

---

## Usage

```text
usage: regscout [-h] [-i IMAGE] [-l LOCKFILE] [-p PKG] [--platform PLATFORM]
                [-f {text,json,markdown}] [--color {auto,always,never}]
                [--no-color] [--min-severity {unknown,low,medium,high,critical}]
                [--fixable-only] [--direct-only] [--no-trigger-scan]
                [--scan-timeout SCAN_TIMEOUT]
                [--fail-on {none,low,medium,high,critical}] [--fail-on-error]
                [-q]
                [images ...]
```

### Exit Codes

- `0` — Scan completed and no findings met `--fail-on` threshold.
- `1` — One or more findings met or exceeded `--fail-on <severity>`.
- `2` — CLI usage error or unsupported/missing `--lockfile`.
- `3` — One or more targets failed to scan or were unscanned when `--fail-on-error` (or `--fail-on`) was specified.

### Examples

```bash
# 1. Scan container images only (Harbor, Quay, GHCR, Docker Hub)
regscout \
  registry.nersc.gov/example/test-image:0.4.0 \
  quay.io/prometheus/prometheus:v2.55.1 \
  ghcr.io/berriai/litellm:main-v1.60.0-stable \
  --min-severity high

# 2. Scan lockfiles only (no container image needed)
regscout \
  --lockfile ./requirements.txt \
  --lockfile ./go.mod \
  --min-severity high

# 3. Scan individual packages only (no image or file needed)
regscout --pkg pypi:pyjwt@2.10,go:golang.org/x/crypto@0.26.0 --min-severity high

# 4. Combine images + lockfiles in a single structured JSON run for an AI agent
regscout \
  --image registry.nersc.gov/example/test-image:0.4.0 \
  --lockfile ./requirements.txt \
  --format json --min-severity high --fail-on-error
```

---

## Running Tests

```bash
python3 -B -m unittest discover -s tests -t . -v
```
