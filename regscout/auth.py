"""Unified Podman and Docker credential resolver for container registries.

Checks standard container runtime auth files and credential helpers in priority order:
1. $REGISTRY_AUTH_FILE (Podman / Skopeo override)
2. $XDG_RUNTIME_DIR/containers/auth.json (Podman session login)
3. ~/.config/containers/auth.json (Podman persistent login)
4. $DOCKER_CONFIG/config.json (Docker custom config dir)
5. ~/.docker/config.json (Docker CLI / Docker Desktop)
6. Credential helpers (`credHelpers` / `credsStore` in the above config files)

Never prints or logs raw credential values.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


def _candidate_auth_files() -> List[Tuple[str, str]]:
    """Return ordered list of (source_label, path) for Podman and Docker auth files."""
    candidates: List[Tuple[str, str]] = []

    reg_auth = os.environ.get("REGISTRY_AUTH_FILE")
    if reg_auth:
        candidates.append(("podman:$REGISTRY_AUTH_FILE", os.path.expanduser(reg_auth)))

    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(
            ("podman:$XDG_RUNTIME_DIR/containers/auth.json", os.path.join(xdg_runtime, "containers", "auth.json"))
        )

    candidates.append(
        ("podman:~/.config/containers/auth.json", os.path.expanduser("~/.config/containers/auth.json"))
    )

    docker_cfg_dir = os.environ.get("DOCKER_CONFIG")
    if docker_cfg_dir:
        candidates.append(
            ("docker:$DOCKER_CONFIG/config.json", os.path.join(os.path.expanduser(docker_cfg_dir), "config.json"))
        )

    candidates.append(("docker:~/.docker/config.json", os.path.expanduser("~/.docker/config.json")))
    return candidates


_DOCKER_HUB_ALIASES = frozenset(
    {
        "docker.io",
        "index.docker.io",
        "registry-1.docker.io",
        "registry.hub.docker.com",
    }
)


def _normalize_host(key: str) -> str:
    """Normalize a registry key from auth.json / config.json to a canonical bare hostname."""
    key = key.strip()
    if "://" in key:
        parsed = urlparse(key)
        host = (parsed.netloc or parsed.path).split("/")[0].lower()
    else:
        host = key.split("/")[0].lower()
    if host in _DOCKER_HUB_ALIASES:
        return "docker.io"
    return host


def _hosts_equivalent(host_a: str, host_b: str) -> bool:
    """Return True if two registry host strings refer to the same registry."""
    return _normalize_host(host_a) == _normalize_host(host_b)


def _invoke_cred_helper(helper_name: str, registry_host: str) -> Optional[str]:
    """Query `docker-credential-<helper_name>` for `registry_host` and return a Basic auth header."""
    binary = f"docker-credential-{helper_name}"
    norm = _normalize_host(registry_host)
    server_urls = [f"https://{registry_host}", registry_host]
    if norm == "docker.io":
        server_urls.insert(0, "https://index.docker.io/v1/")
    for server_url in dict.fromkeys(server_urls):
        try:
            proc = subprocess.run(
                [binary, "get"],
                input=(server_url + "\n").encode("utf-8"),
                capture_output=True,
                timeout=5,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout:
                continue
            payload = json.loads(proc.stdout.decode("utf-8", errors="ignore"))
            username = payload.get("Username") or ""
            secret = payload.get("Secret") or ""
            if username and secret:
                if username == "<token>":
                    return f"Bearer {secret}"
                raw = f"{username}:{secret}".encode("utf-8")
                encoded = base64.b64encode(raw).decode("ascii")
                return f"Basic {encoded}"
        except Exception:
            continue
    return None


def resolve_registry_auth(registry_host: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve an HTTP Authorization header for `registry_host` from Podman or Docker configs.

    Returns:
        (authorization_header, source_label) where `authorization_header` is e.g. `"Basic ..."`
        and `source_label` describes which config source matched (without exposing secrets).
    """
    target = _normalize_host(registry_host)

    for label, path in _candidate_auth_files():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg: Dict = json.load(fh)
        except Exception:
            continue

        # 1. Direct `auths` entries
        auths = cfg.get("auths") or {}
        if isinstance(auths, dict):
            for key, entry in auths.items():
                if not isinstance(entry, dict):
                    continue
                if _normalize_host(key) == target:
                    auth_b64 = entry.get("auth")
                    if auth_b64 and isinstance(auth_b64, str):
                        return f"Basic {auth_b64.strip()}", label
                    username = entry.get("username")
                    password = entry.get("password")
                    if username and password:
                        raw = f"{username}:{password}".encode("utf-8")
                        return f"Basic {base64.b64encode(raw).decode('ascii')}", label
                    identity_token = entry.get("identitytoken")
                    if identity_token:
                        return f"Bearer {identity_token.strip()}", label

        # 2. Registry-specific `credHelpers`
        cred_helpers = cfg.get("credHelpers") or {}
        if isinstance(cred_helpers, dict):
            for key, helper_name in cred_helpers.items():
                if _normalize_host(key) == target and isinstance(helper_name, str) and helper_name:
                    header = _invoke_cred_helper(helper_name, target)
                    if header:
                        return header, f"{label}#credHelper:{helper_name}"

        # 3. Global `credsStore`
        creds_store = cfg.get("credsStore")
        if isinstance(creds_store, str) and creds_store:
            header = _invoke_cred_helper(creds_store, target)
            if header:
                return header, f"{label}#credsStore:{creds_store}"

    return None, None
