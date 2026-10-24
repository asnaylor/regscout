# Agent Guide: `regscout`

`regscout` is a zero-pull, zero-dependency Python CLI tool that scans explicit **container images** (`--image`), **dependency lockfiles** (`--lockfile`), and/or **individual packages** (`--pkg`) for CVEs.

It does **not** crawl directories automatically—pass the exact images, lockfiles, or package specs you want to check in any combination.

---

## 1. Agent Workflow

1. **Identify targets** in the user's project or cluster:
   - Container images from `Dockerfile` (`FROM ...`), Kubernetes manifests (`image: ...`), or `kubectl get pods`.
   - Lockfiles (`go.mod`, `requirements.txt`, `uv.lock`, `poetry.lock`, `package-lock.json`, `Cargo.lock`) or individual packages (`pypi:name@ver`, `go:module@ver`, `npm:pkg@ver`, `crates.io:crate@ver`).
2. **Run `regscout` with `--format json`** (all three target types work standalone or combined):
   ```bash
   # Images + Lockfiles together
   regscout \
     --image registry.nersc.gov/example/test-image:0.4.0 \
     --image ghcr.io/berriai/litellm:main-v1.60.0-stable \
     --lockfile ./requirements.txt \
     --lockfile ./go.mod \
     --format json --min-severity high

   # Lockfiles only (no image required)
   regscout --lockfile requirements.txt --format json --min-severity high

   # Specific packages only (no image or file required)
   regscout --pkg pypi:pyjwt@2.10,pypi:flask@2.2.2 --format json
   ```
3. **Digest & Triage**:
   - Check `summary.incomplete_images`, `summary.incomplete_packages`, and `summary.errors` first—never assume an image with `status != "ok"` is clean.
   - Prioritize findings where `fixed_by` is non-null (`--fixable-only` filters to only fixable CVEs).
   - Recommend concrete version bumps in the relevant `Dockerfile`, Kubernetes YAML, or lockfile.

---

## 2. How `regscout` Scans

1. **Native Registry Scanners (Zero-Pull)**:
   - **Harbor v2 (`registry.nersc.gov`, etc.)**: Verifies Harbor v2 via `/api/v2.0/systeminfo`, queries Trivy `scan_overview` via Harbor REST API v2 using local Podman/Docker credentials (`~/.config/containers/auth.json` or `~/.docker/config.json`), and **auto-triggers a scan (`POST .../scan`) if unscanned**.
   - **Red Hat Quay (`quay.io`)**: Resolves multi-arch manifest lists to `--platform` (default `linux/amd64`) and queries Quay's Clair v4 `/security?vulnerabilities=true` endpoint.
   - **Docker Hub (`docker.io`)**: Resolves the `--platform` digest and queries Docker Scout GraphQL (`https://api.dso.docker.com/v1/graphql`).
2. **Zero-Pull OCI SBOM Attestation (`oci-sbom-osv`)**: For registries without native scan APIs (like `ghcr.io`, `gcr.io`, `registry.k8s.io`), inspects the OCI Image Index for BuildKit/in-toto SPDX or CycloneDX SBOM attestations, extracts all OS and language PURLs, and batch-queries **[OSV.dev](https://osv.dev)**.
3. **Local Trivy Fallback (`trivy-local` + `osv.dev`)**: If an image has neither a native registry scanner nor an attached OCI SBOM attestation, `regscout` never guesses based on GitHub repository names. If `trivy` is installed locally (`shutil.which("trivy")`), `regscout` runs `trivy image --scanners vuln --list-all-pkgs --format json --quiet` and cross-checks extracted OS/language PURLs (including source package PURLs) against live `OSV.dev`. If `trivy` is not installed (or `--no-local-trivy` is set), `regscout` marks the image `status = "unscanned"` and recommends installing `trivy` (`brew install trivy`).
4. **Lockfiles & `--pkg` via `OSV.dev` + `cve.now` (with `trivy fs` fallback)**: Queries both `https://api.osv.dev/v1/querybatch` and `https://cve.now/stack` and merges/deduplicates findings by CVE/GHSA/upstream alias. Falls back to `trivy fs --scanners vuln` when `--lockfile` is passed a directory or third-party lockfile (`yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `composer.lock`, `pom.xml`, etc.).
