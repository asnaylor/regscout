---
name: regscout
description: Scan container images (--image), dependency lockfiles (--lockfile), and packages (--pkg) for CVEs. Queries Harbor v2 Trivy (auto-triggering scans if unscanned), Red Hat Quay Clair, Docker Scout, OCI SBOM Attestations via OSV.dev, local Trivy CLI fallback (with real-time OSV.dev PURL enrichment) when an image lacks a registry scan or SBOM, and OSV.dev + cve.now for lockfiles/packages.
---

# `regscout` Skill

Use `regscout` whenever you need to audit container images, Kubernetes deployments, `Dockerfile` base images, or application dependencies (`go.mod`, `requirements.txt`, `uv.lock`, `poetry.lock`, `package-lock.json`, `Cargo.lock`, or directories/third-party lockfiles via local Trivy) for CVEs.

## Key Principles

1. **Explicit targets (no directory walking by default)**: First inspect the user's manifests (`Dockerfile`, Kubernetes `*.yaml`, `go.mod`, `requirements.txt`, etc.) to identify the images, lockfiles, or packages in use, then pass them explicitly to `regscout`.
2. **Every target flag works standalone or combined**:
   - Images only: `regscout <image1> <image2> --format json`
   - Lockfiles only: `regscout --lockfile path/to/requirements.txt --lockfile path/to/go.mod --format json`
   - Packages only: `regscout --pkg pypi:pyjwt@2.10,go:google.golang.org/grpc@1.79.1 --format json`
   - Combined: pass `--image`, `--lockfile`, and `--pkg` together in a single command.
3. **Zero-pull first, local Trivy fallback when needed**: `regscout` queries remote registry APIs and OCI SBOM attestations over HTTP first; if an image has neither, it falls back to local `trivy image` (+ live `OSV.dev` PURL enrichment) if `trivy` is installed, or marks the image `status = "unscanned"`.

## Commands

```bash
# Full JSON output for agent analysis
regscout \
  --image registry.nersc.gov/library/nersc/tensorflow:ngc-24.05-v1 \
  --image quay.io/prometheus/prometheus:v2.55.1 \
  --lockfile ./requirements.txt \
  --format json --min-severity high

# Filter to only vulnerabilities that have an upstream fix version
regscout <image_or_flags> --format json --min-severity high --fixable-only
```

## Interpreting Results

- **`summary.incomplete_images` / `summary.incomplete_packages` / `summary.errors`**: Non-zero when a target could not be scanned (`auth_required`, `not_found`, `unscanned`, `error`). Never treat an incomplete scan as clean.
- **`images[].scanners_used`**: Shows which sources answered (`harbor-trivy`, `quay-clair`, `docker-scout`, `oci-sbom-osv`, `trivy-local`, `osv.dev`, `cve.now`).
- **`images[].scan_triggered`**: `true` if `regscout` automatically triggered a live Trivy scan on Harbor and waited for it to complete.
- **`findings[].fixed_by`**: Target version(s) that resolve the vulnerability (`null` if no upstream fix exists yet).
