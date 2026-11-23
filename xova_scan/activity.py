"""What AI did on this machine recently, read from the agents' own local logs.

Only aggregates leave this module: counts, program names, web hosts, folder paths and
risk categories. Prompt text, command arguments, file contents and secret values never do.
"""
import hashlib
import ipaddress
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

RISKY = [
    ("delete files (rm -rf)", re.compile(r"\brm\s+-[a-zA-Z]*(r[a-zA-Z]*f|f[a-zA-Z]*r)")),
    ("force push", re.compile(r"\bgit\s+push\b[^;&|]*(--force\b|\s-f\b)")),
    ("pipe download to shell", re.compile(r"\b(curl|wget)\b[^;&]*\|\s*(sudo\s+)?(ba|z)?sh\b")),
    ("sudo", re.compile(r"(^|[;&|]\s*|\s)sudo\s")),
    ("open permissions (chmod 777)", re.compile(r"\bchmod\s+(-R\s+)?0?777\b")),
    ("hard reset (git reset --hard)", re.compile(r"\bgit\s+reset\s+--hard\b")),
    ("drop a database or table", re.compile(r"\bdrop\s+(table|database|schema)\b", re.I)),
]
URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
CODEX_CMD = re.compile(r'cmd\\?"?\s*:\s*\\?"((?:[^"\\]|\\.)*)')
PATCH_FILE = re.compile(r"\*\*\* (?:Update|Add|Delete) File: ([^\n\\]+)")
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
PROGRAM = re.compile(r"^[A-Za-z][A-Za-z0-9._+-]{0,39}$")
TRIVIAL = {"const", "let", "var", "import", "from", "def", "return", "if", "then", "fi", "for", "do", "done", "else",
           "while", "cd", "echo", "printf", "export", "source", ".", "true", "false", "pushd", "popd", "set", "unset", ":"}
SEGMENT = re.compile(r"&&|\|\||;|\|")
HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
NOISE_SUFFIX = (".example", ".test", ".invalid", ".localhost", ".local", ".internal", ".lan")
FAKE = re.compile(r"(.)\1{5,}|example|test|fake|dummy|sample|placeholder|your|redacted|xxxx", re.I)


def _real_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        pass
    if not HOST.match(host) or host == "localhost" or host.endswith(NOISE_SUFFIX):
        return False
    return not re.search(r"(^|\.)example\.[a-z]+$", host)
MAX_LINE = 5_000_000


def _program(cmd: str) -> str:
    for word in cmd.strip().split():
        if "=" in word and not word.startswith(("-", "/", ".")):
            continue  # env assignment
        if word in ("sudo", "env", "time", "nohup", "exec"):
            continue
        return Path(word.strip("'\"(")).name[:40]
    return ""


def _folder(path: str, home: Path) -> str:
    p = Path(path)
    try:
        rel = p.relative_to(home)
        return "~/" + "/".join(rel.parts[:2]) if len(rel.parts) > 1 else "~"
    except ValueError:
        return str(p.parent)


class _Tally:
    def __init__(self, home, token_shape):
        self.home, self.token_shape = home, token_shape
        self.shell = 0
        self.programs, self.risky, self.mcp, self.folders = Counter(), Counter(), Counter(), Counter()
        self.files, self.secret_files = set(), Counter()
        self.domains, self.secret_hashes = Counter(), set()
        self.searches = self.subagents = self.sessions = 0

    def command(self, cmd: str):
        self.shell += 1
        for segment in SEGMENT.split(cmd.split("\n", 1)[0]):  # first line only: heredoc bodies are code, not commands
            prog = _program(segment)
            if prog and prog not in TRIVIAL and PROGRAM.match(prog) and not self.token_shape.search(prog):
                self.programs[prog] += 1
        for label, rx in RISKY:
            if rx.search(cmd):
                self.risky[label] += 1
        self.host_list(URL.findall(cmd))

    def host_list(self, hosts):
        self.domains.update(h.lower().rstrip(".") for h in hosts if h and _real_host(h))

    def file(self, path: str):
        path = path.strip()
        if path and path not in self.files:
            self.files.add(path)
            self.folders[_folder(path, self.home)] += 1

    def secrets(self, line: str, source: Path):
        for m in self.token_shape.finditer(line):
            tok = m.group(0)
            if FAKE.search(tok):
                continue
            # Only a one-way hash is kept in memory, to count unique keys. The key itself is discarded here.
            self.secret_hashes.add(hashlib.sha256(tok.encode()).hexdigest())
            self.secret_files[str(source)] += 1


def _claude_line(t: _Tally, line: str):
    if '"tool_use"' not in line:
        return
    try:
        d = json.loads(line)
    except ValueError:
        return
    msg = d.get("message") if isinstance(d, dict) else None
    blocks = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(blocks, list):
        return
    for b in blocks:
        if not isinstance(b, dict) or b.get("type") != "tool_use":
            continue
        name, inp = str(b.get("name", "")), b.get("input") if isinstance(b.get("input"), dict) else {}
        if name == "Bash" and isinstance(inp.get("command"), str):
            t.command(inp["command"])
        elif name in EDIT_TOOLS and isinstance(inp.get("file_path") or inp.get("notebook_path"), str):
            t.file(inp.get("file_path") or inp.get("notebook_path"))
        elif name == "WebFetch" and isinstance(inp.get("url"), str):
            try:
                t.host_list([urlsplit(inp["url"]).hostname or ""])
            except ValueError:
                pass
        elif name == "WebSearch":
            t.searches += 1
        elif name in ("Agent", "Task"):
            t.subagents += 1
        elif name.startswith("mcp__"):
            t.mcp[name.split("__")[1]] += 1


def _codex_line(t: _Tally, line: str):
    if '"custom_tool_call"' not in line and '"function_call"' not in line and '"local_shell_call"' not in line:
        return
    try:
        d = json.loads(line)
    except ValueError:
        return
    p = d.get("payload") if isinstance(d, dict) else None
    if not isinstance(p, dict) or p.get("type") not in ("custom_tool_call", "function_call", "local_shell_call"):
        return
    name = str(p.get("name", ""))
    body = p.get("input") if isinstance(p.get("input"), str) else p.get("arguments") if isinstance(p.get("arguments"), str) else ""
    if p.get("type") == "local_shell_call" or name in ("exec", "exec_command", "shell"):
        m = CODEX_CMD.search(body)
        t.command(m.group(1).encode().decode("unicode_escape", errors="ignore") if m else "")
    elif name == "apply_patch":
        for f in PATCH_FILE.findall(body):
            t.file(f)
    elif name == "spawn_agent":
        t.subagents += 1
    elif name.startswith("mcp__"):
        t.mcp[name.split("__")[1]] += 1


def _recent(paths, cutoff):
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_mtime >= cutoff and os.path.isfile(p):
            yield p


def _read_lines(t, path, handler, unreadable):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if len(line) > MAX_LINE:
                    continue
                t.secrets(line, path)
                handler(t, line)
    except OSError:
        unreadable.append(str(path))


def activity(home, token_shape, days=30, unreadable=None):
    home = Path(home)
    unreadable = unreadable if unreadable is not None else []
    cutoff = time.time() - days * 86400
    t = _Tally(home, token_shape)
    claude = list(_recent((home / ".claude/projects").glob("*/*.jsonl"), cutoff))
    codex = list(_recent((home / ".codex/sessions").glob("**/*.jsonl"), cutoff))
    t.sessions = len(claude) + len(codex)
    for p in claude:
        _read_lines(t, p, _claude_line, unreadable)
    for p in codex:
        _read_lines(t, p, _codex_line, unreadable)
    for log in _recent((home / "Library/Logs/Claude").glob("mcp-server-*.log"), cutoff):
        server = log.name[len("mcp-server-"):-len(".log")]
        try:
            with open(log, encoding="utf-8", errors="ignore") as fh:
                n = sum(1 for line in fh if '"method":"tools/call"' in line and "from client" in line.lower())
        except OSError:
            unreadable.append(str(log))
            continue
        if n:
            t.mcp[f"{server} (Claude Desktop)"] += n
    return {
        "days": days,
        "sessions": t.sessions,
        "shell_commands": t.shell,
        "top_programs": dict(t.programs.most_common(8)),
        "risky_commands": dict(t.risky),
        "files_changed": len(t.files),
        "top_folders": dict(t.folders.most_common(8)),
        "web_domains": [h for h, _ in t.domains.most_common()],
        "web_searches": t.searches,
        "mcp_tool_calls": dict(t.mcp.most_common()),
        "subagents_started": t.subagents,
        "secrets_in_logs": len(t.secret_hashes),
        "secret_log_files": sorted(t.secret_files),
    }
