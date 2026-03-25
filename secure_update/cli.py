import sys
from pathlib import Path

import click
from loguru import logger

from secure_update.auditor import audit_lock_file, parse_lock_versions
from secure_update.scanner import find_lock_files
from secure_update.timeutil import parse_age_str
from secure_update.upgrader import upgrade_packages


def _configure_logging(loglevel: str, logfile: str | None) -> None:
    logger.remove()
    logger.add(sys.stderr, level=loglevel)
    if logfile:
        logger.add(logfile, level=loglevel)


@click.command()
@click.argument("directories", nargs=-1, type=click.Path(exists=True))
@click.option("--logfile", default=None, help="Optional log file path.")
@click.option("--loglevel", default="INFO", show_default=True, help="Log level.")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be upgraded without running uv lock.",
)
@click.option(
    "--older",
    default="7d",
    show_default=True,
    metavar="AGE",
    help="Only consider package versions older than AGE. Accepts: 7d, 7 days, 24h, 24 hours, 2w, 1m, 1y.",
)
def main(
    directories: tuple[str, ...],
    logfile: str | None,
    loglevel: str,
    dry_run: bool,
    older: str,
) -> None:
    """Scan directories for uv.lock files and upgrade vulnerable packages."""
    _configure_logging(loglevel, logfile)

    try:
        exclude_newer = parse_age_str(older)
    except ValueError as exc:
        logger.error("{}", exc)
        sys.exit(1)

    search_dirs = [Path(d) for d in directories] if directories else [Path()]
    lock_files = find_lock_files(search_dirs)

    if not lock_files:
        logger.warning("No uv.lock files found.")
        return

    for lock_file in lock_files:
        logger.info("Auditing: {}", lock_file)
        vulnerable = audit_lock_file(lock_file)

        if not vulnerable:
            logger.info("No vulnerabilities found in {}", lock_file)
            continue

        old_versions = {pkg.name: pkg.version for pkg in vulnerable}
        logger.info(
            "Found {} vulnerable package(s) in {}",
            len(vulnerable),
            lock_file,
        )

        if dry_run:
            for pkg in vulnerable:
                fix = pkg.highest_fix_version()
                fix_str = f">={fix}" if fix else "no fix available"
                for vuln in pkg.vulns:
                    click.echo(
                        f"{pkg.name} | {pkg.version} | {vuln.id} | dry-run: {fix_str} (exclude-newer: {exclude_newer})"
                    )
            continue

        result = upgrade_packages(lock_file.parent, vulnerable, exclude_newer)
        if result.returncode != 0:
            logger.error("uv lock failed for {}: {}", lock_file, result.stderr.strip())
            continue

        new_versions = parse_lock_versions(lock_file)

        for pkg in vulnerable:
            new_ver = new_versions.get(pkg.name)
            old_ver = old_versions[pkg.name]
            status = (
                new_ver if (new_ver and new_ver != old_ver) else "remains vulnerable"
            )
            for vuln in pkg.vulns:
                click.echo(f"{pkg.name} | {old_ver} | {vuln.id} | {status}")
