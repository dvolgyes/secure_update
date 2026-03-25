import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from loguru import logger

from secure_update.models import Vulnerability, VulnerablePackage


def parse_vulnerabilities(json_data: dict[str, Any]) -> list[VulnerablePackage]:
    """Parse uv-secure JSON output into a list of vulnerable packages.

    Only packages with at least one vulnerability are returned.
    """
    results: list[VulnerablePackage] = []
    for file_entry in json_data.get("files", []):
        for dep in file_entry.get("dependencies", []):
            vulns_raw = dep.get("vulns", [])
            if not vulns_raw:
                continue
            vulns = [
                Vulnerability(
                    id=v["id"],
                    fix_versions=v.get("fix_versions", []),
                )
                for v in vulns_raw
            ]
            results.append(
                VulnerablePackage(
                    name=dep["name"],
                    version=dep["version"],
                    vulns=vulns,
                )
            )
    return results


def parse_lock_versions(lock_file: Path) -> dict[str, str]:
    """Read a uv.lock TOML file and return a {package_name: version} mapping."""
    with lock_file.open("rb") as f:
        data = tomllib.load(f)
    return {
        pkg["name"]: pkg["version"]
        for pkg in data.get("package", [])
        if "name" in pkg and "version" in pkg
    }


def audit_lock_file(lock_file: Path) -> list[VulnerablePackage]:
    """Run uvx uv-secure against lock_file and return vulnerable packages."""
    cmd = ["uvx", "uv-secure", "--format", "json", str(lock_file)]
    logger.debug("Running: {}", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    # uv-secure exits 0 (clean), 1 (maintenance issues only), 2 (vulnerabilities found)
    if result.returncode not in (0, 1, 2):
        logger.error("uv-secure failed for {}: {}", lock_file, result.stderr.strip())
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse uv-secure JSON for {}: {}", lock_file, exc)
        return []
    return parse_vulnerabilities(data)
