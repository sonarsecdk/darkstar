"""Discover profiles on the appliance that will execute them."""
import os
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

import requests

DEFAULT_PROFILE = "default"


def nuclei_directory() -> Path:
    return Path(os.environ.get("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")).resolve()


def zap_policy_directory() -> Path:
    return Path(os.environ.get("ZAP_POLICY_DIR", str(Path.home() / ".ZAP/policies"))).resolve()


def profile_file(directory: Path, identifier: str, suffixes: set[str]) -> Path:
    path = (directory / identifier).resolve()
    if not path.is_relative_to(directory) or path.suffix not in suffixes or not path.is_file():
        raise ValueError("Selected profile is no longer installed")
    return path


def discover_scanner_profiles() -> list[dict]:
    profiles = []

    def add(scanner, identifier=DEFAULT_PROFILE, name="Default"):
        profiles.append({"scanner": scanner, "id": identifier, "name": name})

    binaries = {
        "rustscan": "rustscan", "nikto": "nikto", "wapiti": "wapiti",
        "dalfox": "dalfox", "testssl": "testssl.sh",
        "bbot_passive": "bbot", "bbot_normal": "bbot", "bbot_aggressive": "bbot", "bbot_attack_surface": "bbot",
    }
    for scanner, binary in binaries.items():
        if shutil.which(binary):
            add(scanner)
    if shutil.which("nuclei"):
        root = nuclei_directory()
        if root.is_dir():
            files = sorted(path for path in root.rglob("*") if path.suffix in {".yaml", ".yml"} and path.is_file() and path.resolve().is_relative_to(root) and not any(part.startswith(".") for part in path.relative_to(root).parts) and "workflows" not in path.relative_to(root).parts)
            if files:
                add("nuclei", name="All installed templates")
            for path in files:
                identifier = path.relative_to(root).as_posix()
                add("nuclei", identifier, identifier)
    if shutil.which("zap.sh") or shutil.which("zaproxy"):
        add("zap", name="Recon (spider and passive scan)")
        root = zap_policy_directory()
        for path in sorted(root.glob("*.policy")):
            try:
                profile_file(root, path.name, {".policy"})
                ET.parse(path)
            except (ET.ParseError, OSError, ValueError):
                continue
            add("zap", path.name, f"Active: {path.stem}")
    try:
        response = requests.get(os.environ.get("OPENVAS_API_URL", "http://openvas-api:8008").rstrip('/') + "/scan-configs", timeout=10)
        response.raise_for_status()
        for config in response.json():
            add("openvas", config["id"], config["name"])
    except (requests.RequestException, ValueError, KeyError, TypeError):
        # An unavailable engine is not advertised as a usable configuration.
        pass
    return profiles
