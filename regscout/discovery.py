"""Explicit target parsers for container images (--image), lockfiles (--lockfile), and packages (--pkg)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

ECOSYSTEM_ALIASES: Dict[str, str] = {
    "pip": "pypi",
    "pypi": "pypi",
    "python": "pypi",
    "go": "go",
    "golang": "go",
    "npm": "npm",
    "node": "npm",
    "cargo": "crates.io",
    "rust": "crates.io",
    "crates": "crates.io",
    "crates.io": "crates.io",
}

SUPPORTED_LOCKFILES = (
    "go.mod",
    "requirements.txt / requirements-*.txt / constraints.txt",
    "uv.lock",
    "poetry.lock",
    "package-lock.json / npm-shrinkwrap.json",
    "Cargo.lock",
)

TRIVY_EXTRA_LOCKFILES = (
    "yarn.lock",
    "pnpm-lock.yaml",
    "gemfile.lock",
    "composer.lock",
    "pom.xml",
    "build.gradle.lockfile",
    "podfile.lock",
    "packages.lock.json",
    "mix.lock",
    "pubspec.lock",
    "pipfile.lock",
    "conan.lock",
)


@dataclass
class DiscoveredImage:
    raw: str
    registry: str
    repository: str
    tag: Optional[str]
    digest: Optional[str]


@dataclass
class DiscoveredPackage:
    ecosystem: str  # "go", "pypi", "npm", "crates.io"
    name: str
    version: str
    source: str     # e.g. "--pkg" or "requirements.txt:7"
    direct: bool = True


_REQ_EXACT_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(===|==)\s*([A-Za-z0-9_.+-]+)\s*$"
)
_REQ_UNPINNED_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(~=|>=|<=|!=|>|<|$)"
)
_REQ_FILENAME_RE = re.compile(
    r"^(?:requirements(?:[-_.].*)?|.*[-_.]requirements|constraints(?:[-_.].*)?)\.txt$"
)
_PKG_SPEC_RE = re.compile(r"^([A-Za-z0-9_.-]+):([^@]+)@(.+)$")


def normalize_ecosystem(eco: str) -> Optional[str]:
    return ECOSYSTEM_ALIASES.get(eco.strip().lower())


def parse_image_ref(raw_ref: str) -> Optional[DiscoveredImage]:
    """Parse a container image reference into registry, repository, tag, and digest."""
    ref = raw_ref.strip().strip("'\"")
    if not ref or ref.lower() == "scratch" or "$" in ref or "{" in ref:
        return None

    digest: Optional[str] = None
    tag: Optional[str] = None

    if "@" in ref:
        name_part, digest = ref.split("@", 1)
        if ":" in name_part.split("/")[-1]:
            name_part, tag = name_part.rsplit(":", 1)
    else:
        last_segment = ref.split("/")[-1]
        if ":" in last_segment:
            name_part, tag = ref.rsplit(":", 1)
        else:
            name_part = ref
            tag = "latest"

    parts = name_part.split("/")
    if len(parts) == 1:
        registry = "docker.io"
        repository = f"library/{parts[0]}"
    else:
        first = parts[0]
        if "." in first or ":" in first or first == "localhost":
            registry = first.lower()
            repository = "/".join(parts[1:])
            if registry in ("index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"):
                registry = "docker.io"
            if registry == "docker.io" and "/" not in repository:
                repository = f"library/{repository}"
        else:
            registry = "docker.io"
            repository = "/".join(parts)

    if not repository:
        return None

    return DiscoveredImage(
        raw=ref,
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
    )


def parse_pkg_spec(raw_spec: str) -> List[DiscoveredPackage]:
    """Parse one or more comma-separated `ecosystem:name@version` strings."""
    pkgs: List[DiscoveredPackage] = []
    for item in raw_spec.split(","):
        tok = item.strip()
        if not tok:
            continue
        m = _PKG_SPEC_RE.match(tok)
        if not m:
            raise ValueError(
                f"Invalid --pkg format '{tok}'. Expected <ecosystem>:<name>@<version> "
                f"(e.g. pypi:pyjwt@2.10 or go:google.golang.org/grpc@1.79.1)"
            )
        raw_eco, name, ver = m.group(1), m.group(2).strip(), m.group(3).strip()
        eco = normalize_ecosystem(raw_eco)
        if not eco:
            raise ValueError(
                f"Unsupported ecosystem '{raw_eco}' in '{tok}'. "
                f"Supported: pypi (or pip), go, npm, crates.io (or cargo)."
            )
        if eco == "pypi":
            name = name.lower()
        elif eco == "go":
            ver = ver.lstrip("v")
        pkgs.append(
            DiscoveredPackage(
                ecosystem=eco,
                name=name,
                version=ver,
                source="--pkg",
                direct=True,
            )
        )
    return pkgs


def _parse_go_replace_spec(
    spec_line: str,
    replaces: Dict[Tuple[str, Optional[str]], Optional[Tuple[str, str]]],
) -> None:
    """Parse a single `old [vOld] => new [vNew]` line inside `go.mod`."""
    clean = spec_line.split("//", 1)[0].strip()
    if "=>" not in clean:
        return
    left, right = [part.strip() for part in clean.split("=>", 1)]
    left_parts = left.split()
    right_parts = right.split()
    if not left_parts or not right_parts:
        return
    old_mod = left_parts[0]
    old_ver = left_parts[1].lstrip("v") if len(left_parts) >= 2 else None

    target_mod = right_parts[0]
    if (
        target_mod.startswith("./")
        or target_mod.startswith("../")
        or target_mod.startswith("/")
        or len(right_parts) < 2
    ):
        # Replaced with a local filesystem path -> skip upstream CVE lookup
        replaces[(old_mod, old_ver)] = None
    else:
        target_ver = right_parts[1].lstrip("v")
        replaces[(old_mod, old_ver)] = (target_mod, target_ver)


def _parse_go_mod(path: str, display_path: str) -> List[DiscoveredPackage]:
    raw_reqs: List[Tuple[str, str, str, bool]] = []
    replaces: Dict[Tuple[str, Optional[str]], Optional[Tuple[str, str]]] = {}
    go_patch_ver: Optional[Tuple[str, int]] = None
    toolchain_ver: Optional[Tuple[str, int]] = None

    in_require = False
    in_replace = False

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for idx, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            tc_m = re.match(r"^toolchain\s+go(\d+\.\d+\.\d+)", line)
            if tc_m:
                toolchain_ver = (tc_m.group(1), idx)
                continue

            go_m = re.match(r"^go\s+(\d+\.\d+\.\d+)\b", line)
            if go_m:
                go_patch_ver = (go_m.group(1), idx)
                continue

            if re.match(r"^require\s*\($", line):
                in_require = True
                continue
            if re.match(r"^replace\s*\($", line):
                in_replace = True
                continue
            if (in_require or in_replace) and line.startswith(")"):
                in_require = False
                in_replace = False
                continue

            if line.startswith("replace "):
                _parse_go_replace_spec(line[len("replace ") :].strip(), replaces)
                continue
            if in_replace:
                _parse_go_replace_spec(line, replaces)
                continue

            req_line = None
            if line.startswith("require "):
                req_line = line[len("require ") :].strip()
            elif in_require:
                req_line = line

            if req_line:
                indirect = "// indirect" in req_line
                clean = req_line.split("//", 1)[0].strip()
                parts = clean.split()
                if len(parts) >= 2:
                    mod_name = parts[0]
                    mod_ver = parts[1].lstrip("v")
                    raw_reqs.append((mod_name, mod_ver, f"{display_path}:{idx}", not indirect))

    packages: List[DiscoveredPackage] = []
    chosen_stdlib = toolchain_ver or go_patch_ver
    if chosen_stdlib:
        stdlib_ver, stdlib_line = chosen_stdlib
        packages.append(
            DiscoveredPackage(
                ecosystem="go",
                name="stdlib",
                version=stdlib_ver,
                source=f"{display_path}:{stdlib_line}",
                direct=True,
            )
        )

    for mod_name, mod_ver, src, is_direct in raw_reqs:
        if (mod_name, mod_ver) in replaces:
            rep = replaces[(mod_name, mod_ver)]
            if rep is None:
                continue
            mod_name, mod_ver = rep
        elif (mod_name, None) in replaces:
            rep = replaces[(mod_name, None)]
            if rep is None:
                continue
            mod_name, mod_ver = rep

        packages.append(
            DiscoveredPackage(
                ecosystem="go",
                name=mod_name,
                version=mod_ver,
                source=src,
                direct=is_direct,
            )
        )
    return packages


def _parse_requirements_txt(
    path: str,
    display_path: str,
    warnings: Optional[List[str]] = None,
) -> List[DiscoveredPackage]:
    packages: List[DiscoveredPackage] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for idx, raw_line in enumerate(fh, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            # Strip PEP 508 environment markers (e.g. `; python_version >= "3.10"`) and `--hash`
            line = line.split(";", 1)[0].split("--hash", 1)[0].rstrip("\\").strip()
            if not line:
                continue
            m = _REQ_EXACT_RE.match(line)
            if m:
                pkg_name, _op, pkg_ver = m.group(1), m.group(2), m.group(3)
                packages.append(
                    DiscoveredPackage(
                        ecosystem="pypi",
                        name=pkg_name.lower(),
                        version=pkg_ver,
                        source=f"{display_path}:{idx}",
                        direct=True,
                    )
                )
            elif warnings is not None and _REQ_UNPINNED_RE.match(line):
                warnings.append(
                    f"{display_path}:{idx}: skipped unpinned requirement '{line}' (only exact '==' pins are scanned)"
                )
    return packages


def _load_toml(path: str) -> Optional[Dict[str, Any]]:
    if tomllib is None:
        return None
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _parse_uv_lock(path: str, display_path: str) -> List[DiscoveredPackage]:
    toml_data = _load_toml(path)
    if isinstance(toml_data, dict):
        raw_pkgs = toml_data.get("package") or []
        direct_names: Set[str] = set()
        workspace_names: Set[str] = set()
        for entry in raw_pkgs:
            if not isinstance(entry, dict):
                continue
            name = (entry.get("name") or "").lower()
            src = entry.get("source") or {}
            is_local = isinstance(src, dict) and any(
                k in src for k in ("editable", "virtual", "directory")
            )
            if is_local:
                workspace_names.add(name)
                for dep in entry.get("dependencies") or []:
                    if isinstance(dep, dict) and dep.get("name"):
                        direct_names.add(str(dep["name"]).lower())

        packages: List[DiscoveredPackage] = []
        for entry in raw_pkgs:
            if not isinstance(entry, dict):
                continue
            name = (entry.get("name") or "").lower()
            ver = entry.get("version")
            if not name or not ver or name in workspace_names:
                continue
            is_direct = (name in direct_names) if direct_names else True
            packages.append(
                DiscoveredPackage(
                    ecosystem="pypi",
                    name=name,
                    version=str(ver),
                    source=display_path,
                    direct=is_direct,
                )
            )
        return packages

    # Fallback line parser if tomllib is unavailable
    packages = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        cur_name: Optional[str] = None
        cur_ver: Optional[str] = None
        cur_line = 1
        for idx, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if line == "[[package]]":
                if cur_name and cur_ver:
                    packages.append(
                        DiscoveredPackage(
                            ecosystem="pypi",
                            name=cur_name.lower(),
                            version=cur_ver,
                            source=f"{display_path}:{cur_line}",
                            direct=True,
                        )
                    )
                cur_name = None
                cur_ver = None
                cur_line = idx
            elif line.startswith("name = "):
                cur_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                cur_ver = line.split("=", 1)[1].strip().strip('"')
        if cur_name and cur_ver:
            packages.append(
                DiscoveredPackage(
                    ecosystem="pypi",
                    name=cur_name.lower(),
                    version=cur_ver,
                    source=f"{display_path}:{cur_line}",
                    direct=True,
                )
            )
    return packages


def _parse_poetry_lock(path: str, display_path: str) -> List[DiscoveredPackage]:
    toml_data = _load_toml(path)
    if not isinstance(toml_data, dict):
        raise ValueError(f"Cannot parse {display_path}: tomllib requires Python 3.11+")
    packages: List[DiscoveredPackage] = []
    for entry in toml_data.get("package") or []:
        if not isinstance(entry, dict):
            continue
        name = (entry.get("name") or "").lower()
        ver = entry.get("version")
        if not name or not ver:
            continue
        packages.append(
            DiscoveredPackage(
                ecosystem="pypi",
                name=name,
                version=str(ver),
                source=display_path,
                direct=True,
            )
        )
    return packages


def _parse_package_lock_json(path: str, display_path: str) -> List[DiscoveredPackage]:
    packages: List[DiscoveredPackage] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or (
        "lockfileVersion" not in data and "packages" not in data and "dependencies" not in data
    ):
        raise ValueError(f"File '{display_path}' is not a valid npm package-lock.json")

    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        root_info = pkgs.get("") or {}
        direct_names: Set[str] = set()
        if isinstance(root_info, dict):
            for dep_key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                dep_map = root_info.get(dep_key)
                if isinstance(dep_map, dict):
                    direct_names.update(dep_map.keys())

        for pkg_path, info in pkgs.items():
            if not pkg_path or not isinstance(info, dict):
                continue
            ver = info.get("version")
            if not ver:
                continue
            name = info.get("name") or pkg_path.split("node_modules/")[-1]
            if not name:
                continue
            is_top_node_modules = pkg_path == f"node_modules/{name}"
            if direct_names:
                is_direct = name in direct_names and is_top_node_modules
            else:
                is_direct = is_top_node_modules and not bool(info.get("dev"))
            packages.append(
                DiscoveredPackage(
                    ecosystem="npm",
                    name=name,
                    version=str(ver),
                    source=display_path,
                    direct=is_direct,
                )
            )
        return packages

    # Fallback for npm lockfileVersion 1 ("dependencies" tree)
    deps_v1 = data.get("dependencies")
    if isinstance(deps_v1, dict):
        def _walk_v1(dep_dict: Dict[str, Any], top_level: bool) -> None:
            for name, info in dep_dict.items():
                if not isinstance(info, dict):
                    continue
                ver = info.get("version")
                if ver:
                    packages.append(
                        DiscoveredPackage(
                            ecosystem="npm",
                            name=name,
                            version=str(ver),
                            source=display_path,
                            direct=top_level,
                        )
                    )
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    _walk_v1(nested, False)

        _walk_v1(deps_v1, True)
    return packages


def _parse_cargo_lock(path: str, display_path: str) -> List[DiscoveredPackage]:
    toml_data = _load_toml(path)
    if isinstance(toml_data, dict):
        raw_pkgs = toml_data.get("package") or []
        direct_names: Set[str] = set()
        root_names: Set[str] = set()
        for entry in raw_pkgs:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            src = entry.get("source")
            if not src:
                root_names.add(name)
                for dep in entry.get("dependencies") or []:
                    if isinstance(dep, str):
                        dep_name = dep.split()[0]
                        if dep_name:
                            direct_names.add(dep_name)

        packages: List[DiscoveredPackage] = []
        for entry in raw_pkgs:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            ver = entry.get("version")
            src = entry.get("source")
            if not name or not ver:
                continue
            if not src and root_names:
                # Skip root workspace crate itself
                continue
            is_direct = (name in direct_names) if direct_names else True
            packages.append(
                DiscoveredPackage(
                    ecosystem="crates.io",
                    name=name,
                    version=str(ver),
                    source=display_path,
                    direct=is_direct,
                )
            )
        return packages

    packages = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        cur_name: Optional[str] = None
        cur_ver: Optional[str] = None
        cur_line = 1
        for idx, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if line == "[[package]]":
                if cur_name and cur_ver:
                    packages.append(
                        DiscoveredPackage(
                            ecosystem="crates.io",
                            name=cur_name,
                            version=cur_ver,
                            source=f"{display_path}:{cur_line}",
                            direct=True,
                        )
                    )
                cur_name = None
                cur_ver = None
                cur_line = idx
            elif line.startswith("name = "):
                cur_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                cur_ver = line.split("=", 1)[1].strip().strip('"')
        if cur_name and cur_ver:
            packages.append(
                DiscoveredPackage(
                    ecosystem="crates.io",
                    name=cur_name,
                    version=cur_ver,
                    source=f"{display_path}:{cur_line}",
                    direct=True,
                )
            )
    return packages


def is_trivy_fs_target(path: str) -> bool:
    """Return True if `path` is a directory or a third-party lockfile supported via `trivy fs`."""
    if os.path.isdir(path):
        return True
    if os.path.isfile(path) and os.path.basename(path).lower() in TRIVY_EXTRA_LOCKFILES:
        return True
    return False


def parse_lockfile(
    path: str,
    warnings: Optional[List[str]] = None,
) -> List[DiscoveredPackage]:
    """Parse an explicit lockfile or raise ValueError for unsupported lockfile filenames."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Lockfile not found: {path}")

    fname = os.path.basename(path).lower()
    if fname == "go.mod":
        return _parse_go_mod(path, path)
    if fname == "uv.lock":
        return _parse_uv_lock(path, path)
    if fname == "poetry.lock":
        return _parse_poetry_lock(path, path)
    if fname == "cargo.lock":
        return _parse_cargo_lock(path, path)
    if fname in ("package-lock.json", "npm-shrinkwrap.json"):
        return _parse_package_lock_json(path, path)
    if _REQ_FILENAME_RE.match(fname):
        return _parse_requirements_txt(path, path, warnings=warnings)

    raise ValueError(
        f"Unsupported lockfile format '{path}'. Supported lockfiles: {', '.join(SUPPORTED_LOCKFILES)}"
    )


def resolve_explicit_targets(
    image_refs: List[str],
    lockfile_paths: List[str],
    pkg_specs: List[str],
    warnings: Optional[List[str]] = None,
) -> Tuple[List[DiscoveredImage], List[DiscoveredPackage]]:
    """Parse explicit images, lockfiles, and package specs without walking directories."""
    images_by_key: Dict[str, DiscoveredImage] = {}
    for raw_img in image_refs:
        parsed = parse_image_ref(raw_img)
        if parsed:
            key = f"{parsed.registry}/{parsed.repository}:{parsed.tag or ''}@{parsed.digest or ''}"
            if key not in images_by_key:
                images_by_key[key] = parsed

    packages: List[DiscoveredPackage] = []
    for lf in lockfile_paths:
        packages.extend(parse_lockfile(lf, warnings=warnings))
    for ps in pkg_specs:
        packages.extend(parse_pkg_spec(ps))

    return list(images_by_key.values()), packages
