"""xova-scan: find the AI on this machine and check it against your rules.

Runs locally. Never opens a network connection. Never reads, stores or prints a
secret's value: only the name of the variable or config key that holds it. MCP
commands and URLs are reduced to the program name or scheme://host. Never runs
another program (not even git).
"""
import json
import os
import re
import stat
import tomllib
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

__version__ = "0.1.0"

NOTE = ("Local scan only. Nothing left this machine. Secret values were never read into the report. "
        "Finding nothing does not prove there is no AI here.")

MAX_BYTES = 1_000_000
MAX_DEPTH = 6

AI_APPS = ["ChatGPT", "ChatGPT Classic", "Claude", "Cursor", "Windsurf", "Antigravity", "Ollama", "LM Studio",
           "Perplexity", "Copilot", "Microsoft Copilot", "Gemini", "Jan", "Msty", "Zed", "Warp", "Raycast AI",
           "Superwhisper", "Granola", "Notion AI", "GitHub Copilot"]

AI_LIBRARIES = {
    "openai", "anthropic", "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk", "claude-agent-sdk",
    "google-generativeai", "google-genai", "@google/generative-ai", "@google/genai", "vertexai",
    "mistralai", "@mistralai/mistralai", "cohere", "cohere-ai", "groq", "groq-sdk", "together", "replicate",
    "ollama", "litellm", "langchain", "langchain-core", "langchain-openai", "langchain-anthropic", "@langchain/core",
    "langchain-community", "langgraph", "@langchain/langgraph", "llama-index", "llamaindex", "crewai", "autogen",
    "pyautogen", "ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "transformers", "huggingface-hub",
    "@huggingface/inference", "sentence-transformers", "dspy", "dspy-ai", "instructor", "pydantic-ai",
    "mcp", "@modelcontextprotocol/sdk", "fastmcp", "@aws-sdk/client-bedrock-runtime",
    "@azure/openai", "openai-agents", "@openai/agents", "smolagents", "haystack-ai",
}

ENV_LINE = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=")
KEYISH = re.compile(r"(API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH|CREDENTIAL|(^|_)KEY$)")
AI_KEY_HINT = re.compile(r"OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_API|MISTRAL|COHERE|GROQ|TOGETHER|REPLICATE|"
                         r"HUGGINGFACE|HF_|PERPLEXITY|XAI|DEEPSEEK|AZURE_OPENAI|BEDROCK|OPENROUTER|LANGCHAIN|"
                         r"LANGSMITH|PINECONE|ELEVENLABS|FIREWORKS|VOYAGE")
SECRET_FLAG = re.compile(r"^--?(api[-_]?key|token|access[-_]?token|secret|password|auth|key|bearer)(=|$)", re.I)
TOKEN_SHAPE = re.compile(r"(?<![A-Za-z0-9])(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|"
                         r"xox[abprs]-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{8,}|glpat-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,})")
RANDOM_SHAPE = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-+/=]{20,}$")
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl")

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "site-packages", "dist", "build",
             ".next", ".cache", "Library", ".Trash", "Applications", ".npm", ".cargo", ".rustup", "Pods"}
HIDDEN_ALLOWED = {".vscode", ".cursor", ".config"}
PROJECT_MCP = {(".mcp.json",): "Claude Code (project)", (".vscode", "mcp.json"): "VS Code (project)",
               (".cursor", "mcp.json"): "Cursor (project)"}


class _Unreadable(Exception):
    pass


def _read(path: Path) -> str:
    """Read a regular file, capped. FIFOs, devices and sockets are refused, so nothing can hang the scan."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise _Unreadable(str(path))
        with open(path, "rb") as fh:
            return fh.read(MAX_BYTES).decode("utf-8", errors="ignore")
    except OSError as exc:
        raise _Unreadable(str(path)) from exc


def _home_mcp_sources(home: Path):
    sup = home / "Library/Application Support"
    return [
        ("Claude Desktop", sup / "Claude/claude_desktop_config.json"),
        ("Claude Code", home / ".claude.json"),
        ("Cursor", home / ".cursor/mcp.json"),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json"),
        ("VS Code", sup / "Code/User/mcp.json"),
        ("VS Code", sup / "Code/User/settings.json"),
        ("VS Code Insiders", sup / "Code - Insiders/User/mcp.json"),
        ("VS Code Insiders", sup / "Code - Insiders/User/settings.json"),
        ("Gemini CLI", home / ".gemini/settings.json"),
        ("Codex", home / ".codex/config.toml"),
        ("Zed", home / ".config/zed/settings.json"),
        ("LM Studio", home / ".lmstudio/mcp.json"),
    ]


def _servers(data):
    """Yield (name, config) from every place a client keeps MCP servers."""
    if not isinstance(data, dict):
        return
    for key in ("mcpServers", "servers", "context_servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            yield from ((n, c) for n, c in block.items() if isinstance(c, dict))
    if isinstance(data.get("mcp"), dict):
        yield from _servers(data["mcp"])
    if isinstance(data.get("projects"), dict):
        for proj in data["projects"].values():
            yield from _servers(proj)


def _looks_secret(text: str) -> bool:
    if TOKEN_SHAPE.search(text):
        return True
    return bool(RANDOM_SHAPE.match(text)) and "/" not in text.strip("/") and not text.startswith("-")


def _safe(name):
    """Names are printed, so a name that is itself shaped like a token is redacted."""
    name = str(name)
    return "[redacted: looks like a secret]" if _looks_secret(name) or any(_looks_secret(p) for p in re.split(r"[_\s:=]", name)) else name


def _is_reference(val: str) -> bool:
    v = val.strip()
    return "${" in v or "$env:" in v or "{env:" in v or bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", v))


def _literal(val) -> bool:
    if isinstance(val, list):
        return any(_literal(v) for v in val)
    return isinstance(val, str) and bool(val.strip()) and not _is_reference(val)


def _keyish(name: str) -> bool:
    return bool(KEYISH.search(name.upper().replace("-", "_")))


def _url_target(url: str):
    """Return (scheme://host, carries_secret). Userinfo, path and query never leave this function."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "(unparseable url)", False
    pairs = parse_qsl(parts.query) + parse_qsl(parts.path.split(";", 1)[1] if ";" in parts.path else "")
    secret = bool(parts.username or parts.password or parts.fragment) or \
        any(_keyish(k) or _looks_secret(v) for k, v in pairs) or any(_looks_secret(seg) for seg in parts.path.split("/"))
    return (f"{parts.scheme}://{host}{port}" if host else "(url)"), secret


def _command_target(cmd, args):
    """Return (program name, carries_secret). Arguments are never output."""
    if isinstance(cmd, dict):  # Zed: {"path": ..., "args": [...]}
        args = cmd.get("args", args)
        cmd = cmd.get("path", "")
    program, secret = "", False
    if isinstance(cmd, str):
        words = cmd.split()
        secret = any("=" in w and (_keyish(w.split("=", 1)[0]) or _looks_secret(w.split("=", 1)[1])) for w in words)
        tokens = [t for t in words if "=" not in t]
        program = Path(tokens[0]).name if tokens else ""
    if isinstance(args, list):
        strs = [a for a in args if isinstance(a, str)]
        for i, a in enumerate(strs):
            m = SECRET_FLAG.match(a)
            if m and (m.group(2) == "=" or (i + 1 < len(strs) and not strs[i + 1].startswith("-"))):
                secret = True
            low = a.lower()
            if "authorization" in low or "bearer " in low or any(_looks_secret(p) for p in re.split(r"[\s=:]", a) if p):
                secret = True
    return program or "(unknown command)", secret


class _Report:
    def __init__(self):
        self.found, self.unreadable, self.inline_secrets, self.exposed_keys = [], [], set(), []
        self._seen = set()

    def add(self, kind, name, where, **extra):
        key = (kind, name, where)
        if key in self._seen:
            return
        self._seen.add(key)
        self.found.append({"kind": kind, "name": name, "where": where, "status": "Not reviewed", **extra})


def _scan_mcp_file(client, path, rep):
    try:
        text = _read(path)
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
    except (_Unreadable, ValueError, RecursionError, tomllib.TOMLDecodeError):
        rep.unreadable.append(f"{client}: {path}")
        return
    where = f"{client} ({path})"
    for name, cfg in _servers(data):
        if isinstance(cfg.get("url"), str):
            target, secret = _url_target(cfg["url"])
        else:
            target, secret = _command_target(cfg.get("command"), cfg.get("args"))
        rep.add("mcp_server", _safe(name), where, runs=_safe(target))
        if secret:
            rep.inline_secrets.add(_safe(name))
        for block in ("env", "headers"):
            values = cfg.get(block)
            if not isinstance(values, dict):
                continue
            for key, val in values.items():
                if not isinstance(key, str) or not _keyish(key):
                    continue
                rep.add("api_key", _safe(key), f"{client} config for MCP server '{_safe(name)}' ({path})")
                if _literal(val):
                    rep.inline_secrets.add(_safe(name))


def _scan_apps(apps_dir: Path, rep):
    if not apps_dir.is_dir():
        return
    present = {p.stem for p in apps_dir.glob("*.app")}
    for app in AI_APPS:
        if app in present:
            rep.add("ai_app", app, str(apps_dir / f"{app}.app"))


def _strip_req(req: str) -> str:
    return re.split(r"[\s<>=!~\[;@]", req.strip(), maxsplit=1)[0]


def _deps_from(path: Path):
    text = _read(path)
    if path.name == "package.json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("package.json is not an object")
        deps = []
        for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if isinstance(data.get(k), dict):
                deps += list(data[k])
        return deps
    if path.name == "pyproject.toml":
        data = tomllib.loads(text)
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        reqs = list(project.get("dependencies") or []) if isinstance(project.get("dependencies"), list) else []
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    reqs += group
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            reqs += list(poetry["dependencies"])
        if not isinstance(data.get("project", {}), dict):
            raise ValueError("pyproject [project] is not a table")
        return [_strip_req(r) for r in reqs if isinstance(r, str)]
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            out.append(_strip_req(line))
    return out


def _in_repo(start: Path) -> bool:
    """True if any folder from here up to / holds a .git entry (directory or worktree file).
    We never decide whether git ignores a file: that judgement has too many git internals to copy safely."""
    return any(os.path.lexists(d / ".git") for d in [start, *start.parents])


def _is_env_file(name: str) -> bool:
    if name.lower().endswith(TEMPLATE_SUFFIXES):
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def _scan_projects(roots, rep, home_sources=frozenset()):
    seen_libs = set()
    for root in roots:
        if not root.is_dir():
            continue
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: rep.unreadable.append(str(e.filename))):
            d = Path(dirpath)
            dirnames[:] = [n for n in dirnames if n not in SKIP_DIRS and (not n.startswith(".") or n in HIDDEN_ALLOWED)]
            if len(d.parts) - root_depth >= MAX_DEPTH:
                dirnames[:] = []
            for parts, client in PROJECT_MCP.items():
                if parts[-1] in filenames and (len(parts) == 1 or d.name == parts[0]):
                    cfg = d / parts[-1]
                    if cfg not in home_sources:
                        _scan_mcp_file(client, cfg, rep)
            for f in filenames:
                p = d / f
                if f in ("package.json", "pyproject.toml") or (f.startswith("requirements") and f.endswith(".txt")):
                    try:
                        deps = _deps_from(p)
                    except (_Unreadable, ValueError, TypeError, AttributeError, RecursionError, tomllib.TOMLDecodeError):
                        rep.unreadable.append(str(p))
                        continue
                    for dep in deps:
                        dep = dep.lower()
                        if dep in AI_LIBRARIES and (dep, str(d)) not in seen_libs:
                            seen_libs.add((dep, str(d)))
                            rep.add("ai_library", dep, str(p))
                elif _is_env_file(f):
                    try:
                        lines = _read(p).splitlines()
                    except _Unreadable:
                        rep.unreadable.append(str(p))
                        continue
                    keys = []
                    for line in lines:
                        m = ENV_LINE.match(line.strip())  # only group 1 (the name) is ever kept
                        if m and AI_KEY_HINT.search(m.group(1)) and _keyish(m.group(1)):
                            keys.append(m.group(1))
                    if not keys:
                        continue
                    exposed = _in_repo(d)
                    for key in keys:
                        key = _safe(key)
                        rep.add("api_key", key, str(p))
                        if exposed:
                            rep.exposed_keys.append((key, str(p)))


def _check(rep, rules):
    findings = []
    for key, path in rep.exposed_keys:
        findings.append({"rule": "plaintext-ai-key-in-repo", "subject": key, "where": path,
                         "why": "An AI key is stored in plain text inside a git repository. Confirm it can never be "
                                f"committed: git check-ignore -v \"{path}\" must print a rule, and "
                                "git ls-files must not list it. Better: use a secrets manager."})
    server_where = {}
    for f in rep.found:
        if f["kind"] == "mcp_server":
            server_where.setdefault(f["name"], f["where"])
    for server in sorted(rep.inline_secrets):
        findings.append({"rule": "no-secrets-in-mcp-config", "subject": server, "where": server_where.get(server, ""),
                         "why": "This MCP server's config holds a secret in plain text (env, header, URL or argument). "
                                "Use an environment variable reference."})
    approved = {a.lower() for a in rules.get("approved", [])}
    if approved:
        for item in rep.found:
            if item["kind"] == "api_key":
                continue
            if item["name"].lower() in approved:
                item["status"] = "Approved"
            else:
                findings.append({"rule": "approved-tools-only", "subject": item["name"], "where": item["where"],
                                 "why": "Not on your approved list."})
    return findings


def validate_rules(rules):
    if rules is None:
        return {}
    if not isinstance(rules, dict):
        raise ValueError("rules must be a JSON object, e.g. {\"approved\": [\"Claude\"]}")
    approved = rules.get("approved", [])
    if not isinstance(approved, list) or not all(isinstance(a, str) for a in approved):
        raise ValueError("\"approved\" must be a list of names")
    return rules


def scan(home, apps_dir=Path("/Applications"), roots=None, rules=None):
    home = Path(home)
    rules = validate_rules(rules)
    roots = [Path(r) for r in (roots or [home])]
    rep = _Report()
    for client, path in _home_mcp_sources(home):
        if path.exists():
            _scan_mcp_file(client, path, rep)
    _scan_apps(Path(apps_dir), rep)
    _scan_projects(roots, rep, {p for _, p in _home_mcp_sources(home)})
    findings = _check(rep, rules)
    return {"tool": "xova-scan", "version": __version__, "note": NOTE, "found": rep.found,
            "findings": findings, "unreadable": rep.unreadable, "roots": [str(r) for r in roots]}
