"""
core/logger.py – Coloured console logger + optional file sink.
All messages are timestamped.  Call setup_file_log(path) once at startup
to mirror every message into a plain text file alongside the console.
"""
import sys
import threading
from datetime import datetime
try:
    import colorama
    colorama.init()
except ImportError:
    pass

# ─── ANSI colours ────────────────────────────────────────────────
class Colors:
    RED    = '\033[1;31m'   # Bright Red
    GREEN  = '\033[1;32m'   # Bright Hacker Green
    YELLOW = '\033[1;33m'   # Warning Yellow
    BLUE   = '\033[1;34m'
    CYAN   = '\033[1;36m'
    BOLD   = '\033[1m'
    NC     = '\033[0m'   # reset

# ─── Internal state ──────────────────────────────────────────────
_lock      = threading.Lock()
_log_file  = None          # file handle, set by setup_file_log()
_verbose   = False         # set by set_verbose(True)
error_log  = []            # stores tuple (tool/context, error message)

# ─── Public API ──────────────────────────────────────────────────

def setup_file_log(path: str):
    """Open *path* for append and mirror all log calls to it."""
    global _log_file
    try:
        _log_file = open(path, "a", buffering=1, encoding="utf-8")
        _log_file.write(f"\n{'='*60}\n")
        _log_file.write(f"  Log started: {_ts()}\n")
        _log_file.write(f"{'='*60}\n\n")
    except OSError as e:
        _print_console(f"{Colors.YELLOW}[logger] Cannot open log file {path}: {e}{Colors.NC}")


def set_verbose(v: bool):
    global _verbose
    _verbose = v


def info(msg: str):
    _emit("[*]", f"{Colors.GREEN}{msg}{Colors.NC}", Colors.GREEN)

def success(msg: str):
    _emit("[+]", f"{Colors.BOLD}{Colors.GREEN}{msg}{Colors.NC}", Colors.GREEN)

def warning(msg: str):
    _emit("[!]", f"{Colors.BOLD}{Colors.YELLOW}{msg}{Colors.NC}", Colors.YELLOW)

def error(msg: str, context: str = ""):
    _emit("[X]", f"{Colors.BOLD}{Colors.RED}{msg}{Colors.NC}", Colors.RED)
    if context:
        error_log.append(f"[{_ts()}] [Context: {context}] {msg}")
    else:
        error_log.append(f"[{_ts()}] {msg}")

def dump_errors(path: str):
    """Write all accumulated errors to a file."""
    if not error_log:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("=== VenomRecon Error Log ===\n\n")
            f.write("\n".join(error_log))
    except Exception as e:
        _emit("[X]", f"Could not write error log to {path}: {e}", Colors.RED)

def debug(msg: str):
    if _verbose:
        _emit("[D]", msg, Colors.CYAN)

def phase(num: int, name: str):
    """Pretty phase header printed to both console and file."""
    line = f"{'-'*60}"
    header = f"  [ PHASE {num} ] > {name}"
    # Hacker neon green banner for phases
    _emit_raw(f"\n{Colors.BOLD}{Colors.GREEN}{line}\n{header}\n{line}{Colors.NC}\n")
    if _log_file:
        _log_file.write(f"\n{line}\n{header}\n{line}\n\n")


# ─── Internal helpers ─────────────────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _emit(prefix: str, msg: str, colour: str):
    ts = _ts()
    # Apply colour to the prefix and the actual message so it looks fantastic.
    console_line = f"{colour}{prefix}{Colors.NC} {Colors.GREEN}[{ts}]{Colors.NC} {colour}{msg}{Colors.NC}"
    plain_line   = f"{prefix} [{ts}] {msg}"
    with _lock:
        _print_console(console_line)
        if _log_file:
            try:
                _log_file.write(plain_line + "\n")
            except OSError:
                pass

def _emit_raw(text: str):
    with _lock:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except UnicodeEncodeError:
            enc = sys.stdout.encoding or 'ascii'
            sys.stdout.write(text.encode(enc, errors='replace').decode(enc))
            sys.stdout.flush()

def _print_console(text: str):
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or 'ascii'
        sys.stdout.write((text + "\n").encode(enc, errors='replace').decode(enc))
        sys.stdout.flush()
