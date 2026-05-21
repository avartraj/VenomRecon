"""
utils/helpers.py – Shared utility functions used across autorecon_py.
"""
import os
import time
import shutil
from typing import List


def safe_file_size(path: str) -> int:
    """Return file size in bytes, or 0 if the file doesn't exist."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def count_lines(path: str) -> int:
    """Count non-empty lines in a file; returns 0 if file is missing."""
    try:
        with open(path, "r", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def read_lines_safe(path: str) -> List[str]:
    """Read lines from a file, skipping blanks; never raises."""
    try:
        with open(path, "r", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:
        return []


def is_tool(name: str) -> bool:
    """Return True if *name* is available on PATH."""
    return shutil.which(name) is not None


def banner():
    """Print the VenomRecon banner."""
    b1 = r"""
██    ██ ███████ ███    ██  ██████  ███    ███ ██████   ███████  ██████   ██████  ███    ██
██    ██ ██      ████   ██ ██    ██ ████  ████ ██   ██  ██      ██       ██    ██ ████   ██
██    ██ █████   ██ ██  ██ ██    ██ ██ ████ ██ ██████   █████   ██       ██    ██ ██ ██  ██
 ██  ██  ██      ██  ██ ██ ██    ██ ██  ██  ██ ██   ██  ██      ██       ██    ██ ██  ██ ██
  ████   ███████ ██   ████  ██████  ██      ██ ██   ██  ███████  ██████   ██████  ██   ████
"""
    b2 = r"""
          >>> TERMINATOR EDITION <<<
        ┌─────────────────────────────────────────────────┐
        │  VenomRecon Autonomous Agent  –  Python Edition │
        │  Bug Bounty Reconnaissance Automation Framework │
        └─────────────────────────────────────────────────┘
"""
    try:
        from core.logger import Colors
        print(f"{Colors.BOLD}{Colors.GREEN}{b1}{Colors.RED}{b2}{Colors.NC}")
    except Exception:
        print("VenomRecon Autonomous Agent - Terminator Edition")


class PhaseTimer:
    """Context manager that records and prints elapsed time for a phase."""

    def __init__(self, name: str):
        self.name = name
        self.start = 0.0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *_):
        elapsed = time.time() - self.start
        mins, secs = divmod(int(elapsed), 60)
        from core import logger  # local import to avoid circular
        logger.success(f"{self.name} finished in {mins}m {secs}s")
