"""Ruby / Rails source walker - bug class hypothesis surfacer.

Ruby has no standard-library AST exposed to Python, so this classifier is
line- and regex-based rather than a true AST walk (cf. `ast_python.py`).
It trades precision for recall: the probe contract is to surface
high-recall hypotheses for an LLM auditor or human reviewer to confirm,
not to decide exploitability.

Bug classes covered:

- `cmd_injection`:
    system/exec/spawn, backticks, %x(), IO.popen, Open3.* where a shell
    string is interpolated (`#{...}`) or a shell-spawning helper is used.
- `unsafe_deserialization`:
    Marshal.load/restore, YAML.load/load_file (not safe_load),
    Psych.load, Oj.load.
- `sql_injection_string_interp`:
    ActiveRecord query methods (where/order/find_by_sql/...) and raw
    connection.execute built with string interpolation or concatenation.
- `unsafe_reflection`:
    constantize / const_get / send / public_send with a dynamic argument,
    and eval / instance_eval / class_eval / module_eval.
- `ssrf_open_uri`:
    URI.open, Kernel#open, Net::HTTP / Excon / Faraday with an
    interpolated URL.
- `template_injection`:
    render inline:/text:/html:, ERB.new, raw()/html_safe over interpolation.

A "candidate finding" is `{file, line, bug_class, hypothesis, snippet}`,
matching the shape emitted by `ast_python.scan_file`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# Each rule: (bug_class, compiled_regex, hypothesis).
# Regexes already encode the taint signal (interpolation `#{`, dynamic arg,
# or an inherently dangerous sink) so a match is a reportable hypothesis.
_RULES: list[tuple[str, re.Pattern[str], str]] = [
    # ---- command execution -------------------------------------------------
    (
        "cmd_injection",
        re.compile(r"`[^`]*#\{"),
        "backtick shell command with string interpolation; verify the interpolated value is not attacker-controlled",
    ),
    (
        "cmd_injection",
        re.compile(r"%x[\(\{\[][^)\}\]]*#\{"),
        "%x() shell command with string interpolation; verify the interpolated value is not attacker-controlled",
    ),
    (
        "cmd_injection",
        re.compile(r"\b(system|exec|spawn)\b\s*\(?[^#\n]*#\{"),
        "system/exec/spawn with an interpolated argument; a single-string form spawns a shell - parametrize as an arg array",
    ),
    (
        "cmd_injection",
        re.compile(r"\bIO\.popen\s*\(\s*[\"']?[^\"')]*#\{"),
        "IO.popen with an interpolated command string; pass an argv array instead of a shell string",
    ),
    (
        "cmd_injection",
        re.compile(r"\bOpen3\.(capture2e?|capture3|popen2e?|popen3|pipeline\w*)\b"),
        "Open3 shell helper; confirm arguments are passed as an array, not an interpolated shell string",
    ),
    # ---- deserialization ---------------------------------------------------
    (
        "unsafe_deserialization",
        re.compile(r"\bMarshal\.(load|restore)\s*\("),
        "Marshal.load on untrusted bytes yields arbitrary object instantiation / RCE; require signed or trusted input only",
    ),
    (
        "unsafe_deserialization",
        re.compile(r"\bYAML\.load(_file)?\s*\("),
        "YAML.load (not safe_load) can instantiate arbitrary Ruby objects; use YAML.safe_load with an allowlist",
    ),
    (
        "unsafe_deserialization",
        re.compile(r"\bPsych\.load\s*\("),
        "Psych.load can instantiate arbitrary Ruby objects; use Psych.safe_load",
    ),
    (
        "unsafe_deserialization",
        re.compile(r"\bOj\.load\s*\("),
        "Oj.load defaults to :object mode (arbitrary object instantiation); use mode: :strict or :compat",
    ),
    # ---- SQL injection -----------------------------------------------------
    (
        "sql_injection_string_interp",
        re.compile(
            r"\.(where|find_by_sql|order|reorder|group|having|joins|select|pluck|"
            r"exists\?|count_by_sql|update_all|delete_all|from|lock)\s*\(?\s*[\"'][^\n]*?#\{"
        ),
        "ActiveRecord query built with string interpolation; use bind parameters (?/:named) or sanitize_sql",
    ),
    (
        "sql_injection_string_interp",
        re.compile(
            r"\bconnection\.(execute|exec_query|select_all|select_value|select_values|"
            r"select_one|exec_update|exec_delete)\s*\(\s*[\"'][^\n]*?#\{"
        ),
        "raw SQL via connection.execute built with string interpolation; parametrize the query",
    ),
    (
        "sql_injection_string_interp",
        re.compile(r"\.(where|order|group|having)\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        "ActiveRecord query built with string concatenation; use bind parameters instead",
    ),
    # ---- reflection / eval -------------------------------------------------
    (
        "unsafe_reflection",
        re.compile(r"(?<![\"'])\.constantize\b"),
        "constantize on a dynamic value can instantiate attacker-chosen classes; allowlist permitted constants",
    ),
    (
        "unsafe_reflection",
        re.compile(r"\bconst_get\s*\("),
        "const_get with a dynamic name can resolve attacker-chosen constants; allowlist permitted names",
    ),
    (
        "unsafe_reflection",
        re.compile(r"\.(send|public_send|__send__)\s*\(\s*[^\"':)\s]"),
        "send/public_send with a non-literal method name can invoke arbitrary methods; allowlist callable methods",
    ),
    (
        "unsafe_reflection",
        re.compile(r"(?<![\w.])(eval|instance_eval|class_eval|module_eval)\s*\("),
        "eval-family call; if the argument derives from input this is arbitrary code execution",
    ),
    # ---- SSRF --------------------------------------------------------------
    (
        "ssrf_open_uri",
        re.compile(r"\bURI\.open\s*\("),
        "URI.open (open-uri) fetches a remote URL; if the URL is attacker-controlled this is SSRF - route through SSRFResolver",
    ),
    (
        "ssrf_open_uri",
        re.compile(r"(?<![\w.])open\s*\(\s*[\"']?[^\"')]*#\{"),
        "Kernel#open with an interpolated argument: SSRF if a URL, command injection if the value starts with '|'",
    ),
    (
        "ssrf_open_uri",
        re.compile(r"\bNet::HTTP\.(get|post|get_response|start)\s*\([^)]*#\{"),
        "Net::HTTP request to an interpolated URL/host; if attacker-controlled this is SSRF - validate against SSRFResolver",
    ),
    (
        "ssrf_open_uri",
        re.compile(r"\b(Excon|Faraday)\.(get|post|new|run)\s*\([^)]*#\{"),
        "HTTP client request to an interpolated URL; if attacker-controlled this is SSRF",
    ),
    # ---- template injection / XSS -----------------------------------------
    (
        "template_injection",
        re.compile(r"\brender\s+(inline|text|html|body):"),
        "render inline:/text:/html: bypasses template auto-escaping; verify the rendered value is not attacker-controlled",
    ),
    (
        "template_injection",
        re.compile(r"\bERB\.new\s*\("),
        "ERB.new on a dynamic template string is server-side template injection if the template derives from input",
    ),
    (
        "template_injection",
        re.compile(r"\braw\s*\([^)]*#\{|#\{[^}]*\}[^\"']*[\"']\s*\.html_safe"),
        "raw()/html_safe over interpolated content disables HTML escaping; stored XSS if the value is attacker-controlled",
    ),
]


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") and not stripped.startswith("#{")


def _snippet(lines: list[str], lineno: int, before: int = 1, after: int = 2) -> str:
    start = max(0, lineno - 1 - before)
    end = min(len(lines), lineno - 1 + after + 1)
    return "\n".join(f"{i + 1:>5}  {lines[i]}" for i in range(start, end))


def scan_file(path: Path, *, repo_root: Path | None = None) -> list[dict[str, Any]]:
    try:
        source = path.read_text(errors="replace")
    except OSError as exc:
        return [{
            "file": str(path),
            "line": 0,
            "bug_class": "parse_error",
            "hypothesis": f"file failed to read: {exc}",
            "snippet": "",
        }]
    rel_path = str(path.relative_to(repo_root)) if repo_root else str(path)
    lines = source.splitlines()
    findings: list[dict[str, Any]] = []
    for idx, line in enumerate(lines):
        if _is_comment_line(line):
            continue
        seen: set[str] = set()
        for bug_class, pattern, hypothesis in _RULES:
            if bug_class in seen:
                continue
            if pattern.search(line):
                seen.add(bug_class)
                findings.append({
                    "file": rel_path,
                    "line": idx + 1,
                    "bug_class": bug_class,
                    "hypothesis": hypothesis,
                    "snippet": _snippet(lines, idx + 1),
                })
    return findings


def scan_files(files: list[Path], *, repo_root: Path, max_files: int | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for i, path in enumerate(files):
        if max_files is not None and i >= max_files:
            break
        findings.extend(scan_file(path, repo_root=repo_root))
    return findings
