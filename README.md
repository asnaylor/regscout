# regscout

**Find known vulnerabilities in container images, lockfiles, and packages, from your terminal or your AI coding agent.**

Point `regscout` at the images you run (or build), the lockfiles in your repo, or individual packages. It reports each CVE with a severity, the installed version, and the version that fixes it. It reads scan results that registries already have, so for most images **nothing is pulled and no Docker daemon is needed**.

**Built for agents as well as humans.** Run it yourself, or ask your coding agent (Claude Code, Codex, Cursor, ...) to run it. Agents get structured `--format json` output that never reports an unscanned target as clean, plus a ready-made [skill](skills/regscout/SKILL.md) and [`AGENTS.md`](AGENTS.md). For example:

> Use regscout to scan the images in my `k8s/` manifests and my `requirements.txt`, and tell me which versions to upgrade to.

See [With an AI agent](#with-an-ai-agent) for setup.

```bash
regscout postgres:16 quay.io/prometheus/prometheus:v2.55.1 --min-severity critical
```

```text
✗ postgres:16  [docker-scout]
  Summary  : 4 total (4 fixable) — 4 CRITICAL
  Recommended Upgrades:
    • stdlib                     1.24.6 -> 1.26.9  (4 CRITICAL)
  Fixable Findings:
    SEV       CVSS  ID              PACKAGE       VERSION -> FIX     SUMMARY
    CRITICAL  10.0  CVE-2025-68121  stdlib        1.24.6 -> 1.24.13  During session resumption in crypto/tls, if the…
    ...

✗ quay.io/prometheus/prometheus:v2.55.1  [quay-clair]
  Summary  : 9 total (9 fixable) — 9 CRITICAL
  Recommended Upgrades:
    • golang.org/x/crypto        v0.26.0 -> 0.52.0  (8 CRITICAL)
    • google.golang.org/grpc     v1.66.0 -> 1.79.3  (1 CRITICAL)
  ...
```

Output is a snapshot; CVE data changes daily, so your results will differ.

---

## Install

Requires Python 3.9+ and has no third-party dependencies.

```bash
git clone <this-repo> && cd regscout
uv tool install .        # or: pipx install .   /   pip install -e .
regscout --help

# or run without installing
python3 -m regscout --help
```

> [!NOTE]
> Trivy is optional but recommended. Without [`trivy`](https://trivy.dev) (`brew install trivy`), images that have no registry scan or SBOM attestation are reported `unscanned`. With it, `regscout` falls back to `trivy image`, which **downloads the image layers**. See [How it works](docs.md#how-it-works).

---

## Quickstart

```bash
# Container images you use (positional or --image, any registry)
regscout postgres:16 ghcr.io/berriai/litellm:main-v1.60.0-stable

# A private NERSC Harbor image (log in first: `podman login registry.nersc.gov`)
regscout registry.nersc.gov/library/nersc/tensorflow:ngc-24.05-v1 --min-severity high

# Dependencies in your repo
regscout --lockfile requirements.txt --lockfile go.mod --min-severity high

# A package you're thinking of using, or want to double-check
regscout --pkg pypi:pyjwt@2.10.0,npm:lodash@4.17.20 --min-severity high

# Only show what you can actually fix
regscout postgres:16 --fixable-only --min-severity high
```

Images, lockfiles, and packages can be combined in one command.

The NERSC example above reports (scanned server-side by Harbor's Trivy, nothing pulled):

```text
! registry.nersc.gov/library/nersc/tensorflow:ngc-24.05-v1  [harbor-trivy]
  Summary  : 2 total (2 fixable) — 2 HIGH
  Recommended Upgrades:
    • Newtonsoft.Json            12.0.3 -> 13.0.1  (1 HIGH)
    • jupyterlab                 2.3.2 -> 3.0.8  (1 HIGH)
```

### Scanning images you built

`regscout` asks registries about images, so an image that only exists in your local Docker daemon can't be scanned. Two options:

1. **Push it, then scan it.** `docker push ghcr.io/you/app:1.2.3 && regscout ghcr.io/you/app:1.2.3`. Build with `--sbom=true` (BuildKit) so the registry carries an SBOM attestation, which gives accurate OS and language package coverage on registries without their own scanner (GHCR, GCR, ...).
2. **Scan what goes into it.** Run `regscout --lockfile requirements.txt` (or `go.mod`, `package-lock.json`, ...) on the lockfiles your Dockerfile installs from, and `regscout <base-image>` on its `FROM` image.

### Scanning what you already run

Ask `regscout` to check the images referenced in your Dockerfiles or Kubernetes manifests:

```bash
grep -rhoE 'image: *\S+' k8s/ | awk '{print $2}' | sort -u | xargs regscout --min-severity high
```

### In CI

```bash
regscout ghcr.io/you/app:1.2.3 --lockfile requirements.txt \
  --min-severity high --fixable-only --fail-on high --fail-on-error
```

See [exit codes](docs.md#exit-codes) for what each result means.

### With an AI agent

Install the CLI, then give your agent the skill in [`skills/regscout/SKILL.md`](skills/regscout/SKILL.md) (for Claude Code, copy it to `~/.claude/skills/regscout/SKILL.md`; other agents read [`AGENTS.md`](AGENTS.md)). Then ask in plain language:

> Scan the images in my `k8s/` manifests and my `requirements.txt` with regscout and tell me which upgrades to make.

The agent runs `regscout --format json`, checks that every target was actually scanned, and proposes version bumps. See [`AGENTS.md`](AGENTS.md) for the JSON schema.

---

## More

See [`docs.md`](docs.md) for [output formats and the JSON shape](docs.md#output-formats), [exit codes](docs.md#exit-codes), [all options and supported lockfiles](docs.md#options), [how scanning works](docs.md#how-it-works), and [privacy](docs.md#privacy).
