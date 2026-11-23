"""What AI did on this machine recently, read from the agents' own local logs.

Only aggregates leave this module: counts, program names, web hosts, folder paths and
risk categories. Prompt text, command arguments, file contents and secret values never do.
"""
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
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
URL = re.compile(r"https?://[^\s\"'<>|;`)]+")
CODEX_CMD = re.compile(r'cmd\\?"?\s*:\s*\\?"((?:[^"\\]|\\.)*)')
PATCH_FILE = re.compile(r"\*\*\* (?:Update|Add|Delete) File: ([^\n\\]+)")
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
KNOWN = set("""ls cat head tail grep rg sed awk find xargs sort uniq wc cut tr diff patch git gh npm npx pnpm yarn bun node deno
python python3 pip pip3 pipx uv uvx pytest ruby go cargo rustc make cmake docker kubectl terraform aws gcloud az curl wget ssh scp
rsync tar zip unzip gzip mkdir rm cp mv ln touch chmod chown open osascript brew jq yq sqlite3 psql mysql redis-cli ps kill pkill
lsof top du df env which date sleep bash sh zsh code cursor claude codex vercel netlify supabase firebase flyctl heroku stripe
playwright java javac mvn gradle dotnet swift xcodebuild pod ffmpeg convert magick tee less more nl stat file basename dirname
realpath mktemp seq printenv pmset launchctl defaults security plutil sw_vers uname whoami hostname id test nc ping dig
nslookup openssl base64 shasum md5 sha256sum perl php composer lua R julia""".split())
_WHICH = {}


def _named_program(prog: str) -> str:
    """Name a program only if it is a well-known tool or actually installed; anything else is 'other',
    so a password or private note typed as a command can never appear. shutil.which only checks files."""
    if prog in KNOWN:
        return prog
    if prog not in _WHICH:
        _WHICH[prog] = bool(PROGRAM.match(prog)) and shutil.which(prog) is not None
    return prog if _WHICH[prog] else "other"


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
    from . import _safe
    p = Path(path)
    try:
        parts = p.parent.relative_to(home).parts[:2]
        prefix = "~/"
    except ValueError:
        parts = [x for x in p.parent.parts if x != "/"][:2]
        prefix = "/"
    return prefix + "/".join(_safe(x) for x in parts) if parts else prefix.rstrip("/") or "/"


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
            if prog and prog not in TRIVIAL:
                self.programs[_named_program(prog)] += 1
        for label, rx in RISKY:
            if rx.search(cmd):
                self.risky[label] += 1
        hosts = []
        for url in URL.findall(cmd):
            try:
                hosts.append(urlsplit(url).hostname or "")
            except ValueError:
                pass
        self.host_list(hosts)

    def host_list(self, hosts):
        from . import _looks_secret
        for h in hosts:
            h = (h or "").lower().rstrip(".")
            if h and _real_host(h) and not any(_looks_secret(label) for label in h.split(".")):
                self.domains[h] += 1

    def mcp_call(self, server: str):
        from . import _safe
        self.mcp[_safe(server)] += 1

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
    except (ValueError, RecursionError):
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
            t.mcp_call(name.split("__")[1])


def _codex_line(t: _Tally, line: str):
    if '"custom_tool_call"' not in line and '"function_call"' not in line and '"local_shell_call"' not in line:
        return
    try:
        d = json.loads(line)
    except (ValueError, RecursionError):
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
        t.mcp_call(name.split("__")[1])


def _recent(paths, cutoff):
    """Regular files only: symlinks, FIFOs and devices are never opened, so nothing outside the agent folders is read."""
    for p in paths:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mtime >= cutoff:
            yield p


def _read_lines(t, path, handler, unreadable):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            while True:
                line = fh.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE and not line.endswith("\n"):
                    while (rest := fh.readline(MAX_LINE)) and not rest.endswith("\n"):
                        pass  # skip the rest of an oversized line without holding it in memory
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
        from . import _safe
        server = _safe(log.name[len("mcp-server-"):-len(".log")])
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
        "top_programs": dict((k, v) for k, v in t.programs.most_common(9) if k != "other"),
        "unnamed_program_runs": t.programs.get("other", 0),
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
