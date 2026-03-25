from pathlib import Path

from loguru import logger
from tqdm import tqdm


def find_lock_files(dirs: list[Path]) -> list[Path]:
    """Recursively find all uv.lock files under the given directories."""
    results: list[Path] = []
    for directory in tqdm(dirs, desc="Scanning directories", unit="dir", leave=False):
        if not directory.is_dir():
            logger.warning("Skipping non-directory: {}", directory)
            continue
        logger.debug("Scanning directory: {}", directory)
        found = sorted(directory.rglob("uv.lock"))
        logger.debug("Found {} lock file(s) in {}", len(found), directory)
        results.extend(found)
    return results
