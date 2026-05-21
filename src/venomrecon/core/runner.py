"""
core/runner.py – Reliable subprocess wrapper for autorecon_py.

Key improvements over v1:
  • run()         – kills the entire process group on timeout (not just the parent)
  • run_pipe()    – same, runs arbitrary shell pipelines
  • run_many()    – runs a list of commands concurrently with ThreadPoolExecutor
  • write_file()  – atomic write (write to .tmp then rename)
  • read_lines()  – never raises; returns []
  • append_unique() – deduplication across many source files
"""

import os
import re
import shutil
import signal
import shlex
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Callable, Union
import time

from core import logger
from core.config import config


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

missing_tools_run = set()


def get_install_hint(tool: str) -> str:
    """Dynamically fetch the install hint for a tool from the doctor registry."""
    try:
        from commands.doctor import TOOL_REGISTRY
        if tool in TOOL_REGISTRY:
            return TOOL_REGISTRY[tool][1]
    except Exception:
        pass
    return "go install ... or pip install ... or apt install ..."


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _first_token(cmd: Union[str, List[str]]) -> str:
    """Extract the executable name from a command string or list."""
    if isinstance(cmd, list):
        return cmd[0] if cmd else ""
    return cmd.strip().split()[0] if cmd.strip() else ""


def sanitize_domain(domain: str) -> str:
    """Validate a plain domain name and reject shell metacharacters."""
    cleaned = domain.strip().lower()
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[a-zA-Z0-9.\-]+", cleaned):
        raise ValueError(f"Invalid domain: {domain!r}")
    if ".." in cleaned or cleaned.startswith(".") or cleaned.endswith("."):
        raise ValueError(f"Invalid domain: {domain!r}")
    return cleaned


def build_cmd(tool: str, *args: object) -> List[str]:
    """Build a list-form command and log the shell-escaped display form."""
    cmd = [str(tool), *(str(arg) for arg in args)]
    logger.debug("CMD: " + " ".join(shlex.quote(part) for part in cmd))
    return cmd


def _timeout_for(cmd: Union[str, List[str]], explicit: Optional[int]) -> int:
    if explicit is not None:
        return explicit
    tool = _first_token(cmd)
    return int(config.tool_timeouts.get(tool, config.tool_timeouts.get("default", 300)))


def _start_process(cmd: Union[str, List[str]], shell: bool = True) -> subprocess.Popen:
    """
    Start a process.  On POSIX we use os.setsid so we can kill the whole
    process group cleanly; on Windows we use CREATE_NEW_PROCESS_GROUP.
    """
    kwargs: dict = dict(
        args=cmd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if os.name == "posix":
        kwargs["preexec_fn"] = os.setsid
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(**kwargs)


def _kill(proc: subprocess.Popen):
    """Kill a process (and its group on POSIX)."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────
# Primary run primitives
# ─────────────────────────────────────────────────────────────────

def run(
    cmd: Union[str, List[str]],
    output_file: Optional[str] = None,
    shell: Optional[bool] = None,
    timeout: int = None,
    append: bool = True,
    stdin_data: Optional[str] = None,
) -> str:
    """
    Run a shell or list-form command.

    • Skips gracefully if the tool is not on PATH.
    • Kills the full process group on timeout.
    • Returns stdout as a stripped string (empty on failure).
    • If *output_file* is given, appends (or writes) stdout to that path.
    """
    if isinstance(cmd, list):
        cmd = [str(x) for x in cmd]
        tool_name = cmd[0]
        cmd_display = " ".join(shlex.quote(part) for part in cmd)
        shell = False
    else:
        tool_name = _first_token(cmd)
        cmd_display = cmd
        if shell is None:
            shell = True

    # Check availability – strip leading env overrides (KEY=val cmd …)
    binary = tool_name if "=" not in tool_name else _first_token(tool_name.split(None, 1)[-1])
    if not _tool_exists(binary):
        missing_tools_run.add(binary)
        hint = get_install_hint(binary)
        logger.warning(f"[!] Tool '{binary}' is MISSING! Skipping: {cmd_display[:80]}")
        logger.warning(f"    Install Hint: {hint}")
        return ""

    timeout = _timeout_for(cmd, timeout)
    logger.debug(f"RUN: {cmd_display[:120]}")
    if stdin_data:
        logger.debug(f"RUN Stdin data: {stdin_data[:100]}...")
    if config.dry_run:
        logger.info(f"[DRY-RUN] {cmd_display}")
        return ""
    if config.inter_tool_delay:
        time.sleep(config.inter_tool_delay)
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            shell=shell,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            **({"preexec_fn": os.setsid} if os.name == "posix" else
               {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}),
        )
        try:
            stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.communicate()
            logger.warning(f"Timed out after {timeout}s: {cmd_display[:80]}")
            logger.error(f"Process skipped due to timeout ({timeout}s)", context=tool_name)
            return ""

        output = stdout.strip()
        if output and output_file:
            _write_output(output_file, output + "\n", append=append)

        if proc.returncode != 0 and stderr:
            logger.debug(f"STDERR [{binary}]: {stderr[:200].strip()}")

        return output

    except FileNotFoundError:
        logger.error(f"Tool not found (FileNotFoundError): {binary}", context=tool_name)
        return ""
    except Exception as e:
        logger.error(f"run() error [{cmd_display[:80]}]: {e}", context=tool_name)
        return ""


def run_pipe(
    cmd: str,
    validated_inputs: dict = None,
    output_file: Optional[str] = None,
    outfile: Optional[str] = None,
    timeout: int = None,
    append: bool = True,
) -> str:
    """
    Run an arbitrary shell pipeline (uses shell=True).
    Returns stdout as a stripped string.
    """
    timeout = _timeout_for(cmd, timeout)
    if validated_inputs is None:
        validated_inputs = {"legacy": "call site not yet migrated; input validation must be reviewed"}
    logger.debug(f"PIPE: {cmd[:120]}")
    logger.debug(f"PIPE validated inputs: {validated_inputs}")
    if outfile and not output_file:
        output_file = outfile
    if config.dry_run:
        logger.info(f"[DRY-RUN] {cmd}")
        return ""
    if config.inter_tool_delay:
        time.sleep(config.inter_tool_delay)
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            **({"preexec_fn": os.setsid} if os.name == "posix" else
               {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}),
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.communicate()
            logger.warning(f"Pipe timed out after {timeout}s: {cmd[:80]}")
            logger.error(f"Pipeline skipped due to timeout ({timeout}s)", context="run_pipe")
            return ""

        output = stdout.strip()
        if output and output_file:
            _write_output(output_file, output + "\n", append=append)
        return output

    except Exception as e:
        logger.error(f"run_pipe() error [{cmd[:80]}]: {e}", context="run_pipe")
        return ""


def run_shell_pipeline(
    pipeline: str,
    outfile: str = None,
    timeout: int = 300,
    dry_run: bool = False,
    risk_note: str = "",
) -> subprocess.CompletedProcess:
    """
    Execute a documented shell pipeline as a last-resort compatibility path.

    Shell pipelines must not contain raw user-controlled values. Callers must
    sanitize domain values and resolve file paths before interpolation.
    """
    if not risk_note:
        raise ValueError(
            "run_shell_pipeline() requires a non-empty risk_note documenting "
            "why shell=True is necessary and what input validation was applied."
        )
    command = pipeline if not outfile else f"{pipeline} > {shlex.quote(outfile)}"
    logger.debug(f"SHELL PIPELINE: {command}")
    logger.debug(f"SHELL PIPELINE risk note: {risk_note}")
    if dry_run or config.dry_run:
        logger.info(f"[DRY-RUN] {command}")
        return subprocess.CompletedProcess(command, 0, "", "")
    proc = subprocess.run(
        command,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0 and proc.stderr:
        logger.debug(f"SHELL PIPELINE STDERR: {proc.stderr[:200].strip()}")
    return proc


def run_many(
    commands: Dict[str, dict],
    max_workers: int = 6,
) -> Dict[str, str]:
    """
    Run multiple commands concurrently.

    *commands* is a mapping of  label -> dict(cmd=..., output_file=..., timeout=...)
    Returns a dict of  label -> stdout string.

    Example:
        results = run_many({
            "subfinder": dict(cmd="subfinder -d target.com -silent", output_file="out.txt"),
            "assetfinder": dict(cmd="assetfinder --subs-only target.com", output_file="out2.txt"),
        }, max_workers=4)
    """
    results: Dict[str, str] = {}
    if not commands:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                run,
                v.get("cmd", ""),
                v.get("output_file"),
                None,
                v.get("timeout", 3600),
                True,
                v.get("stdin_data"),
            ): k
            for k, v in commands.items()
        }
        for fut in as_completed(futures):
            label = futures[fut]
            try:
                results[label] = fut.result()
            except Exception as e:
                logger.error(f"run_many [{label}]: {e}", context=label)
                results[label] = ""
    return results


def run_parallel_tasks(
    tasks: List[Callable],
    max_workers: int = None,
    phase_name: str = "",
    fail_fast: bool = False,
) -> dict:
    """
    Run zero-argument callables in parallel and isolate task failures.

    Returns {"results": [...], "errors": [...], "completed": int, "failed": int}.
    """
    if not tasks:
        return {"results": [], "errors": [], "completed": 0, "failed": 0}

    workers = max_workers or config.threads
    phase = phase_name or "parallel"
    results = []
    errors = []
    logger.info(f"Starting {phase}: {len(tasks)} task(s), {workers} worker(s)")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(task): idx for idx, task in enumerate(tasks)}
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                results.append(fut.result())
                logger.debug(f"{phase}: task {idx} finished")
            except Exception as exc:
                msg = f"{phase}: task {idx} failed: {exc}"
                logger.error(msg, context=phase)
                errors.append({"task": idx, "error": str(exc)})
                if fail_fast:
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
                    break

    return {
        "results": results,
        "errors": errors,
        "completed": len(results),
        "failed": len(errors),
    }


# ─────────────────────────────────────────────────────────────────
# File I/O utilities
# ─────────────────────────────────────────────────────────────────

def _write_output(path: str, content: str, append: bool = True):
    """Write content to *path*, creating parent dirs as needed."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)


def write_file(path: str, content: str, mode: str = "w"):
    """Write *content* to *path* with an atomic rename on POSIX."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    if os.name == "posix":
        tmp = path + ".tmp"
        with open(tmp, mode, encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
    else:
        with open(path, mode, encoding="utf-8") as f:
            f.write(content)


def read_lines(path: str) -> List[str]:
    """Read non-empty lines from *path*; returns [] if file is missing."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def append_unique(src_files: List[str], dest: str) -> int:
    """
    Read all *src_files*, deduplicate lines, write to *dest*.
    Returns the count of unique lines written.
    """
    seen: set = set()
    lines: List[str] = []
    for fp in src_files:
        for line in read_lines(fp):
            if line not in seen:
                seen.add(line)
                lines.append(line)
    write_file(dest, "\n".join(lines) + "\n" if lines else "")
    return len(lines)
