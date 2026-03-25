import subprocess
from datetime import date
from pathlib import Path

from loguru import logger

from secure_update.models import VulnerablePackage


def build_upgrade_args(
    packages: list[VulnerablePackage],
    exclude_newer: date | None = None,
) -> list[str]:
    """Build uv lock flags for upgrading vulnerable packages.

    Returns --upgrade-package flags plus an optional --exclude-newer flag.
    Packages without any fix version are skipped.
    """
    args: list[str] = []
    for pkg in packages:
        fix = pkg.highest_fix_version()
        if fix is None:
            logger.warning("No fix version known for {}, skipping upgrade", pkg.name)
            continue
        args.extend(["--upgrade-package", f"{pkg.name}>={fix}"])
    if exclude_newer is not None:
        args.extend(["--exclude-newer", exclude_newer.isoformat()])
    return args


def upgrade_packages(
    lock_dir: Path,
    packages: list[VulnerablePackage],
    exclude_newer: date | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run uv lock --upgrade-package ... [--exclude-newer DATE] in lock_dir."""
    upgrade_args = build_upgrade_args(packages, exclude_newer)
    cmd = ["uv", "lock", *upgrade_args]
    logger.debug("Running in {}: {}", lock_dir, " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, cwd=lock_dir)
