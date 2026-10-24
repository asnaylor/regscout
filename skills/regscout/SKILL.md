---
name: regscout
description: Scan container images (--image), dependency lockfiles (--lockfile), and packages (--pkg) for CVEs without pulling container layers locally. Queries Harbor v2 Trivy (auto-triggering scans if unscanned), Red Hat Quay Clair, Docker Scout, OCI SBOM Attestations via OSV.dev, GitHub Security Advisories (via verified OCI labels), and OSV.dev + cve.now.
---

# `regscout` Skill

Use `regscout` whenever you need to audit container images, Kubernetes deployments, `Dockerfile` base images, or application dependencies (`go.mod`, `requirements.txt`, `uv.lock`, `poetry.lock`, `package-lock.json`, `Cargo.lock`) for CVEs.

## Key Principles

1. **Explicit targets (no directory walking)**: First inspect the user's manifests (`Dockerfile`, Kubernetes `*.yaml`, `go.mod`, `requirements.txt`, etc.) to identify the images, lockfiles, or packages in use, then pass them explicitly to `regscout`.
2. **Every target flag works standalone or combined**:
   - Images only: `regscout <image1> <image2> --format json`
   - Lockfiles only: `regscout --lockfile path/to/requirements.txt --lockfile path/to/go.mod --format json`
   - Packages only: `regscout --pkg pypi:pyjwt@2.10,go:google.golang.org/grpc@1.79.1 --format json`
   - Combined: pass `--image`, `--lockfile`, and `--pkg` together in a single command.
3. **Never pull container images locally**: `regscout` queries remote registry APIs, OCI SBOM attestations, and OCI config labels over HTTP.

## Commands

```bash
# Full JSON output for agent analysis
regscout \
  --image registry.nersc.gov/example/test-image:0.4.0 \
  --image quay.io/prometheus/prometheus:v2.55.1 \
  --lockfile ./requirements.txt \
  --format json --min-severity high

# Filter to only vulnerabilities that have an upstream fix version
regscout <image_or_flags> --format json --min-severity high --fixable-only
```

## Interpreting Results

- **`summary.incomplete_images` / `summary.incomplete_packages` / `summary.errors`**: Non-zero when a target could not be scanned (`auth_required`, `not_found`, `unscanned`, `error`). Never treat an incomplete scan as clean.
- **`images[].scanners_used`**: Shows which sources answered (`harbor-trivy`, `quay-clair`, `docker-scout`, `oci-sbom-osv`, `github-advisories`, `osv.dev`, `cve.now`).
- **`images[].upstream_repo`**: Verified GitHub repository from OCI `org.opencontainers.image.source` labels or `ghcr.io` image path.
- **`images[].scan_triggered`**: `true` if `regscout` automatically triggered a live Trivy scan on Harbor and waited for it to complete.
- **`findings[].fixed_by`**: Target version(s) that resolve the vulnerability (`null` if no upstream fix exists yet).
