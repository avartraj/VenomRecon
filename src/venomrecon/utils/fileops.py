"""File merge, deduplication, and cleanup helpers."""

import os
from typing import Callable, Iterable

from core import logger
from core.config import config


def atomic_write(path: str, lines: Iterable[str]) -> None:
    """Write lines to path.tmp, then replace the destination atomically."""
    if config.dry_run:
        logger.info(f"[DRY-RUN] write {path}")
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(str(line).rstrip("\n") + "\n")
    os.replace(tmp, path)


def safe_delete(path: str) -> bool:
    """Delete a file if it exists and return whether it was removed."""
    if not os.path.exists(path):
        return False
    if config.dry_run:
        logger.info(f"[DRY-RUN] delete {path}")
        return True
    try:
        os.remove(path)
        logger.debug(f"Deleted {path}")
        return True
    except OSError as exc:
        logger.warning(f"Could not delete {path}: {exc}")
        return False


def merge_deduplicate_and_cleanup(
    source_files: list[str],
    output_file: str,
    sort: bool = True,
    delete_sources: bool = True,
    min_line_length: int = 1,
    filter_fn: Callable[[str], bool] = None,
) -> int:
    """Merge source files into a deduplicated output file and optionally remove inputs."""
    total_bytes = 0
    lines = []
    seen = set()
    existing_sources = [path for path in source_files if os.path.isfile(path)]

    for path in existing_sources:
        try:
            total_bytes += os.path.getsize(path)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if len(line) < min_line_length:
                        continue
                    if filter_fn and not filter_fn(line):
                        continue
                    if line not in seen:
                        seen.add(line)
                        lines.append(line)
        except OSError as exc:
            logger.warning(f"Could not read {path}: {exc}")

    if sort:
        lines = sorted(lines)

    atomic_write(output_file, lines)
    wrote_ok = config.dry_run or (os.path.isfile(output_file) and (len(lines) == 0 or os.path.getsize(output_file) > 0))

    deleted_bytes = 0
    if delete_sources and wrote_ok:
        for path in existing_sources:
            if os.path.abspath(path) == os.path.abspath(output_file):
                continue
            try:
                deleted_bytes += os.path.getsize(path)
            except OSError:
                pass
            safe_delete(path)

    saved_kb = max(0, deleted_bytes) // 1024
    logger.info(
        f"Merged {len(existing_sources)} files -> {output_file} "
        f"({len(lines)} unique lines, saved {saved_kb} KB)"
    )
    return len(lines)
