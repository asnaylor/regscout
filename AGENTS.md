# Agent Guide: `regscout`

`regscout` is a zero-dependency Python CLI that scans explicit **container images**, **dependency lockfiles** (`--lockfile`), and/or **individual packages** (`--pkg`) for CVEs. It does **not** crawl directories: pass exactly the targets you want checked, in any combination.

Install and examples are in [`README.md`](README.md); all CLI options, supported lockfiles/registries, exit codes, and how each scanner works are in [`docs.md`](docs.md). This file covers only what an agent needs to run it and read the result.

---

## 1. Workflow

1. **Identify targets** in the user's project or cluster:
   - Images: `FROM` lines in `Dockerfile`s, `image:` fields in Kubernetes manifests or Helm values, or `kubectl get pods -A -o jsonpath='{..image}'`.
   - Lockfiles: `go.mod`, `requirements.txt`, `uv.lock`, `poetry.lock`, `package-lock.json`, `Cargo.lock` (plus directories and `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `composer.lock`, `pom.xml`, etc. when `trivy` is installed).
   - Packages: `pypi:name@ver`, `go:module@ver`, `npm:pkg@ver`, `crates.io:crate@ver`.
2. **Run with `--format json`** (targets work standalone or combined):
   ```bash
   regscout \
     --image postgres:16 \
     --image ghcr.io/berriai/litellm:main-v1.60.0-stable \
     --lockfile ./requirements.txt \
     --pkg pypi:pyjwt@2.10.0 \
     --format json --min-severity high
   ```
   For private registries the user must have run `docker login` / `podman login`; `regscout` reads those credentials.
3. **Check completeness first.** If `summary.incomplete_images`, `summary.incomplete_packages`, or `summary.errors` is non-empty, say which targets weren't scanned and why (`images[].status`, `images[].notes`). Never describe a target with `status != "ok"` as clean.
4. **Triage and recommend.** Prioritize by severity, then findings with a non-null `fixed_by` (`--fixable-only` filters to these). Propose concrete version bumps in the relevant `Dockerfile`, Kubernetes YAML, or lockfile, and mention findings with no fix.

An image that only exists in the local Docker daemon can't be scanned; suggest pushing it, or scan its lockfiles and base image instead.

---

## 2. JSON output

```text
summary:  images_scanned, incomplete_images, packages_scanned, incomplete_packages,
          total_findings, fixable_findings, by_severity{CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN},
          errors[], warnings[]
images[]: image, registry, repository, tag, digest, status, notes[], scanners_used[],
          scan_triggered, auth_source, findings[]
vulnerable_packages[]: ecosystem, name, version, source, direct, status, notes[], findings[]
findings[]: id, severity, cvss, package, version, fixed_by, title, source, aliases[]
```

- `images[].status`: `ok`, `auth_required`, `not_found`, `unscanned`, `error`. `vulnerable_packages[].status`: `ok` or `error`.
- `scanners_used` / `findings[].source` values: `harbor-trivy`, `quay-clair`, `docker-scout`, `oci-sbom-osv`, `trivy-local`, `osv.dev`, `cve.now`.
- `scan_triggered`: `true` if `regscout` started a Harbor scan and waited for it.
- `fixed_by`: version(s) that resolve the CVE, or `null` if no upstream fix exists.
- `warnings` includes skipped `requirements.txt` lines that aren't exact `==` pins.
