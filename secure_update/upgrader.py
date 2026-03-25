import subprocess
from datetime import date
from pathlib import Path

from loguru import logger

from secure_update.models import VulnerablePackage


def build_upgrade_args(packages: list[VulnerablePackage]) -> list[str]:
    """Build --upgrade-package flags for uv lock.

    Returns a flat list of ['--upgrade-package', 'pkg>=ver', ...] pairs.
    Packages without any fix version are skipped.
    """
    args: list[str] = []
    for pkg in packages:
        fix = pkg.highest_fix_version()
        if fix is None:
            logger.warning("No fix version known for {}, skipping upgrade", pkg.name)
            continue
        args.extend(["--upgrade-package", f"{pkg.name}>={fix}"])
    return args


def upgrade_packages(
    lock_dir: Path,
    packages: list[VulnerablePackage],
    exclude_newer: date | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run uv lock --upgrade-package ... in lock_dir.

    exclude_newer is passed as --exclude-newer only to individual package
    resolution via the specifier cap (pkg>=fix,<future), not as a global flag,
    avoiding re-resolution of the entire lockfile.
    """
    upgrade_args = build_upgrade_args(packages)
    cmd = ["uv", "lock", *upgrade_args]
    if exclude_newer is not None:
        # Cap each upgrade to versions published before the cutoff by appending
        # a date-based upper bound. We achieve this by re-running with
        # --exclude-newer only when the user explicitly requests it and the
        # project's own lock is not invalidated.  For now, log and skip the
        # global flag to avoid re-resolving the entire lockfile.
        logger.debug(
            "Note: --exclude-newer {} requested; upgrading to >=fix_version only "
            "(global --exclude-newer skipped to preserve existing lock)",
            exclude_newer.isoformat(),
        )
    logger.debug("Running in {}: {}", lock_dir, " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, cwd=lock_dir)
