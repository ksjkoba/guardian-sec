"""Vulnerability & code scanning module — SLM-powered static analysis."""

from __future__ import annotations

import ast
import re
import threading
from pathlib import Path
from typing import Callable, Iterator

from guardian.engine.alert import Alert, Severity
from guardian.engine.slm import get_engine

MODULE = "code_scanner"

_MAX_CHUNK_LINES = 80    # lines per SLM chunk
_MAX_FILE_SIZE = 512_000  # skip files larger than 512 KB

# Language detection
_LANG_EXTS: dict[str, str] = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".php": "PHP", ".rb": "Ruby", ".go": "Go", ".rs": "Rust",
    ".java": "Java", ".c": "C", ".cpp": "C++", ".cs": "C#",
    ".sh": "Bash", ".yaml": "YAML", ".yml": "YAML",
    ".json": "JSON", ".tf": "Terraform", ".env": "DotEnv",
    ".conf": "Config", ".cfg": "Config", ".ini": "Config",
    ".xml": "XML", ".sql": "SQL", ".dockerfile": "Dockerfile",
}

# Known bad patterns per language for cheap pre-filtering
_BAD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"eval\s*\(", re.I), "eval() usage"),
    (re.compile(r"exec\s*\(", re.I), "exec() usage"),
    (re.compile(r"os\.system\s*\(", re.I), "os.system() call"),
    (re.compile(r"subprocess.*shell\s*=\s*True", re.I), "shell=True subprocess"),
    (re.compile(r"pickle\.(loads?|dumps?)", re.I), "pickle deserialization"),
    (re.compile(r"yaml\.load\s*\([^,)]*\)", re.I), "unsafe yaml.load"),
    (re.compile(r"(md5|sha1)\s*\(", re.I), "weak hash function"),
    (re.compile(r"password\s*=\s*[\"'][^\"']+[\"']", re.I), "hardcoded password"),
    (re.compile(r"secret\s*=\s*[\"'][^\"']{8,}[\"']", re.I), "hardcoded secret"),
    (re.compile(r"api_key\s*=\s*[\"'][^\"']+[\"']", re.I), "hardcoded API key"),
    (re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE KEY-----"), "private key in source"),
    (re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*\+\s*[a-z_]+", re.I), "SQL string concatenation"),
    (re.compile(r"innerHTML\s*=\s*[^\"']", re.I), "XSS via innerHTML"),
    (re.compile(r"document\.write\s*\(", re.I), "document.write XSS"),
    (re.compile(r"fmt\.Sprintf\s*\([\"'].*%s", re.I), "format string in Go"),
    (re.compile(r"\.query\s*\([^,]+%s", re.I), "SQL format string"),
    (re.compile(r"random\.(random|randint|choice)\s*\(", re.I), "weak random (crypto context)"),
    (re.compile(r"http://", re.I), "plaintext HTTP URL"),
    (re.compile(r"verify\s*=\s*False", re.I), "TLS verification disabled"),
    (re.compile(r"allow_redirects\s*=\s*True.*auth", re.I), "credential redirect leak"),
    (re.compile(r"(chmod|os\.chmod).*0o?[67][67][67]", re.I), "world-writable permission"),
    (re.compile(r"(root|admin)\s*:\s*\$", re.I), "shadow file pattern"),
]


def _detect_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if path.name.lower() == "dockerfile":
        return "Dockerfile"
    return _LANG_EXTS.get(suffix, "Unknown")


def _chunk_lines(lines: list[str], chunk_size: int) -> list[list[str]]:
    return [lines[i : i + chunk_size] for i in range(0, len(lines), chunk_size)]


def _build_prompt(language: str, path: Path, chunk: list[str], start_line: int, context: str) -> str:
    code = "\n".join(f"{start_line + i:4d} | {l}" for i, l in enumerate(chunk))
    return (
        f"Perform a security code review of this {language} code from file `{path.name}`.\n"
        f"Pre-scan context: {context}\n\n"
        "Look for: SQL injection, XSS, command injection, path traversal, IDOR, "
        "hardcoded secrets, insecure deserialization, broken auth, cryptographic weaknesses, "
        "SSRF, XXE, open redirect, privilege escalation, race conditions.\n\n"
        "Return a JSON object for the MOST CRITICAL finding (or null if no real vulnerability):\n"
        "{\n"
        '  "title": "vulnerability name",\n'
        '  "description": "what the vulnerability is and how it could be exploited",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "evidence": "the exact vulnerable line(s)",\n'
        '  "recommendation": "how to fix it"\n'
        "}\n\n"
        f"Code:\n```{language.lower()}\n{code}\n```"
    )


def scan_file(path: str | Path) -> Iterator[Alert]:
    """Scan a single source file for vulnerabilities. Yields Alerts."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    if path.stat().st_size > _MAX_FILE_SIZE:
        return

    language = _detect_language(path)
    if language == "Unknown":
        return

    try:
        content = path.read_text(errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    engine = get_engine()

    for chunk_idx, chunk in enumerate(_chunk_lines(lines, _MAX_CHUNK_LINES)):
        start_line = chunk_idx * _MAX_CHUNK_LINES + 1
        chunk_text = "\n".join(chunk)

        # Pre-filter: only send to SLM if there are suspicious patterns
        matched = [desc for pat, desc in _BAD_PATTERNS if pat.search(chunk_text)]
        if not matched:
            continue

        context = f"Pre-scan matched: {', '.join(matched[:5])}"
        raw = engine.analyze(
            _build_prompt(language, path, chunk, start_line, context),
            max_tokens=350,
        )
        if raw.strip().lower() == "null":
            continue
        alert = Alert.from_slm_json(
            MODULE, raw,
            fallback_evidence=f"Lines {start_line}-{start_line + len(chunk) - 1} in {path}"
        )
        if alert:
            alert.metadata.update({
                "file": str(path),
                "language": language,
                "start_line": start_line,
                "matched_patterns": matched,
            })
            yield alert


def scan_directory(
    directory: str | Path,
    extensions: list[str] | None = None,
    exclude: list[str] | None = None,
) -> Iterator[Alert]:
    """Recursively scan a directory for vulnerable code. Yields Alerts."""
    directory = Path(directory)
    exclude_set = set(exclude or [])
    target_exts = set(extensions) if extensions else set(_LANG_EXTS.keys())

    for path in directory.rglob("*"):
        if any(part in exclude_set for part in path.parts):
            continue
        if path.suffix.lower() not in target_exts and path.name.lower() != "dockerfile":
            continue
        if not path.is_file():
            continue
        yield from scan_file(path)


def scan_config(path: str | Path) -> Iterator[Alert]:
    """Scan a config/env file for misconfigurations and secrets."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    content = path.read_text(errors="replace")
    lines = content.splitlines()
    engine = get_engine()

    prompt = (
        f"Security audit of configuration file `{path.name}`.\n"
        "Look for: hardcoded credentials, weak settings, exposed secrets, "
        "insecure defaults, TLS disabled, debug mode on, world-readable permissions.\n\n"
        "Return a JSON object for each finding (return an array), or an empty array []:\n"
        "[\n"
        "  {\n"
        '    "title": "finding name",\n'
        '    "description": "what is wrong",\n'
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '    "evidence": "the specific config line",\n'
        '    "recommendation": "how to fix"\n'
        "  }\n"
        "]\n\n"
        f"Config file:\n```\n{content[:3000]}\n```"
    )

    import json

    raw = engine.analyze(prompt, max_tokens=500)
    try:
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start == -1 or end == 0:
            return
        findings = json.loads(raw[start:end])
        for item in findings:
            alert = Alert.from_slm_json(MODULE, "{" + raw[start + 1: end - 1].strip() + "}")
            if not alert:
                # build manually
                from guardian.engine.alert import Severity

                try:
                    sev = Severity(item.get("severity", "MEDIUM").upper())
                except ValueError:
                    sev = Severity.MEDIUM
                alert = Alert(
                    module=MODULE,
                    title=item.get("title", "Config issue"),
                    description=item.get("description", ""),
                    severity=sev,
                    evidence=item.get("evidence", ""),
                    recommendation=item.get("recommendation", ""),
                    metadata={"file": str(path)},
                )
            yield alert
    except (json.JSONDecodeError, TypeError):
        return
