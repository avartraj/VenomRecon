"""Pure-Python replacements for common shell one-liners."""

import os
import re
import shutil
import urllib.parse


def grep_file(path: str, pattern: str, invert: bool = False) -> list[str]:
    if not os.path.isfile(path):
        return []
    regex = re.compile(pattern)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    if invert:
        return [line.rstrip("\n") for line in lines if not regex.search(line)]
    return [line.rstrip("\n") for line in lines if regex.search(line)]


def grep_files(paths: list[str], pattern: str) -> list[str]:
    seen = set()
    results = []
    regex = re.compile(pattern)
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if regex.search(line) and line not in seen:
                    seen.add(line)
                    results.append(line)
    return results


def awk_column(path: str, col: int, delimiter: str = None) -> list[str]:
    results = []
    if not os.path.isfile(path):
        return results
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(delimiter) if delimiter else line.strip().split()
            if len(parts) >= col:
                results.append(parts[col - 1])
    return results


def sed_replace(path: str, pattern: str, replacement: str, outpath: str = None) -> None:
    if not os.path.isfile(path):
        return
    regex = re.compile(pattern)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    dest = outpath or path
    with open(dest, "w", encoding="utf-8") as f:
        f.write(regex.sub(replacement, content))


def head_lines(path: str, n: int) -> list[str]:
    lines = []
    if not os.path.isfile(path):
        return lines
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= n:
                break
            lines.append(line.rstrip("\n"))
    return lines


def cat_files(paths: list[str]) -> list[str]:
    lines = []
    for path in paths:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines.extend(line.rstrip("\n") for line in f)
    return lines


def move_file(src: str, dst: str) -> None:
    shutil.move(src, dst)


def filter_by_status_code(httpx_output_path: str, codes: list[int]) -> list[str]:
    results = []
    if not os.path.isfile(httpx_output_path):
        return results
    code_strs = {str(code) for code in codes}
    with open(httpx_output_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1].strip("[]") in code_strs:
                results.append(parts[0])
    return results


def extract_urls_from_file(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    url_re = re.compile(r"^https?://", re.IGNORECASE)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if url_re.match(line.strip())]


def filter_scope(urls: list[str], base_domain: str) -> list[str]:
    results = []
    base = base_domain.lower().lstrip("*.")
    for url in urls:
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            host = host.lower()
            if host == base or host.endswith("." + base):
                results.append(url)
        except Exception:
            pass
    return results
