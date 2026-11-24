"""xova-scan: find the AI on this machine and check it against your rules.

Runs locally. Never opens a network connection. Never reads, stores or prints a
secret's value: only the name of the variable or config key that holds it. MCP
commands and URLs are reduced to the program name or scheme://host. Never runs
another program (not even git).
"""
import json
import os
import platform
import shutil
import re
import shlex
import stat
import tomllib
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

__version__ = "0.4.1"

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
                         r"xox[abprs]-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{8,}|glpat-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}|"
                         r"A[KS]IA[0-9A-Z]{16}|[rs]k_(?:live|test)_[0-9A-Za-z]{10,})")
RANDOM_SHAPE = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-+/=]{20,}$")
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl")

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "site-packages", "dist", "build",
             ".next", ".cache", "Library", ".Trash", "Applications", ".npm", ".cargo", ".rustup", "Pods"}
HIDDEN_ALLOWED = {".vscode", ".cursor", ".config"}
MEDIA_SUFFIXES = (".photoslibrary", ".musiclibrary", ".tvlibrary", ".photoboothlibrary", ".imovielibrary", ".fcpbundle")
MEDIA_TOP = {"Movies", "Music", "Pictures"}  # macOS media folders: protected, never hold code
PROJECT_MCP = {(".mcp.json",): "Claude Code (project)", (".vscode", "mcp.json"): "VS Code (project)",
               (".cursor", "mcp.json"): "Cursor (project)"}


CAPABILITIES = [  # (what it can reach, words in the server name or package). Checked in order; first match wins.
    ("your whole desktop", ("computer-use", "computer_use", "computeruse")),
    ("run any command", ("node_repl", "shell", "terminal", "desktop-commander", "exec", "repl", "ssh")),
    ("code repositories", ("github", "gitlab", "bitbucket", "server-git")),
    ("databases", ("supabase", "postgres", "mysql", "sqlite", "mongo", "redis", "neon", "database", "sql",
                   "bigquery", "snowflake", "airtable", "firebase")),
    ("web browser", ("playwright", "puppeteer", "chrome-devtools", "browser", "selenium")),
    ("messages and email", ("slack", "gmail", "discord", "outlook", "teams", "email", "telegram", "whatsapp")),
    ("files on this machine", ("filesystem", "obsidian", "server-fs", "notes", "drive", "dropbox")),
    ("the web", ("firecrawl", "perplexity", "fetch", "brave", "search", "context7", "exa", "tavily", "glif")),
    ("cloud and sites", ("webflow", "figma", "vercel", "aws", "azure", "gcp", "cloudflare", "netlify", "stripe",
                         "shopify", "blender", "notion", "linear", "jira", "atlassian")),
]
RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx"}


def _word(w: str):
    return re.compile(r"(?<![a-z0-9])" + re.escape(w).replace("\\-", "[-_]").replace("_", "[-_]") + r"(?![a-z0-9])")


CAPABILITY_RX = [(label, [_word(w) for w in words]) for label, words in CAPABILITIES]


def _capability(name: str, args) -> str:
    """Whole-word match, so 'replicate' is not 'repl' and 'executive' is not 'exec'."""
    hay = " ".join([name] + [a for a in (args if isinstance(args, list) else []) if isinstance(a, str)]).lower()
    for label, patterns in CAPABILITY_RX:
        if any(p.search(hay) for p in patterns):
            return label
    return "other tools"


def _unpinned(program: str, args) -> bool:
    """A runner (npx, uvx, ...) that fetches a package without an exact version gets new code on every launch."""
    if program not in RUNNERS or not isinstance(args, list):
        return False
    pkgs = [a for a in args if isinstance(a, str) and not a.startswith("-")]
    if not pkgs:
        return False
    pkg = pkgs[0]
    if program in ("uvx", "pipx"):
        return "==" not in pkg and not re.search(r"@\d", pkg)
    body = pkg[1:] if pkg.startswith("@") else pkg
    if "@" not in body:
        return True
    version = body.rsplit("@", 1)[1]
    return version in ("latest", "next", "") or not re.match(r"\d", version)


# A whole package spec, name plus an optional version/tag/range. No ':' '/' '@' or space after the name, so
# URLs, file:, github:, npm: aliases and "name @ url" never parse as a registry package.
NPM_SPEC = re.compile(r"((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)(?:@[A-Za-z0-9^~<>=*][A-Za-z0-9.+_~^<>=*|-]*)?")
_PEP440 = r"(?:===|==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+!_-]+"
PYPI_SPEC = re.compile(rf"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[A-Za-z0-9,._-]+\])?"
                       rf"(?:{_PEP440}(?:,{_PEP440})*|@[A-Za-z0-9][A-Za-z0-9.+_-]*)?")
# Only flags known to take no value may come before the package; any other flag could take the next word.
NO_VALUE_FLAGS = {"npx": {"-y", "--yes", "-q", "--quiet"}, "pnpx": {"-y", "--yes", "-q", "--quiet"},
                  "bunx": {"-y", "--yes", "--bun"}, "uvx": {"-q", "--quiet", "--isolated", "--offline", "--no-cache"},
                  "pipx": {"-q", "--quiet"}}
FILE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".zip", ".whl", ".py")
REGISTRY_ENV = re.compile(r"(?i)npm_config_(registry|@.*:registry)|uv_(default_)?index(_url)?|uv_extra_index_url|"
                          r"pip_(extra_)?index_url|pip_find_links|uv_find_links|bun_config_registry|"
                          r"npm_config_(user|global)config|uv_config_file|pip_config_file|uv_override|uv_constraint")


def _package(program: str, args, env=None):
    """Registry identity of what a runner fetches ("npm:@playwright/mcp", "pypi:mcp-server-fetch"), or None.

    A false identity is worse than none, so this is an allowlist: a known runner, only no-value flags
    before the spec, a whole spec that parses as a plain public-registry package, and no registry
    override in the server's env. Anything else gives None. A project .npmrc/pip.conf is not read.
    """
    if program not in RUNNERS or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    if isinstance(env, dict) and any(isinstance(k, str) and REGISTRY_ENV.fullmatch(k) for k in env):
        return None
    words = list(args)
    if program == "pipx":
        if not words or words[0] != "run":
            return None
        words = words[1:]
    allowed = NO_VALUE_FLAGS[program]
    while words and words[0].startswith("-"):
        flag = words.pop(0)
        if flag == "--":
            break
        if flag not in allowed:
            return None
    if not words:
        return None
    spec = words[0]
    if spec.lower().endswith(FILE_SUFFIXES):
        return None
    if program in ("uvx", "pipx"):
        m = PYPI_SPEC.fullmatch(spec)
        if not m or len(m.group(1)) > 214:
            return None
        name = m.group(1)
        ident = "pypi:" + re.sub(r"[-_.]+", "-", name).lower()
    else:
        m = NPM_SPEC.fullmatch(spec)
        if not m or len(m.group(1)) > 214:
            return None
        name = m.group(1)
        ident = "npm:" + name
    return ident if _safe(ident) == ident and not _looks_secret(name) else None


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


def _app_support(home: Path, system: str) -> Path:
    """Where desktop apps keep settings: macOS Application Support, Windows AppData/Roaming, Linux ~/.config."""
    if system == "Windows":
        return home / "AppData/Roaming"
    if system == "Darwin":
        return home / "Library/Application Support"
    return home / ".config"


def claude_desktop_logs(home: Path, system: str) -> Path:
    if system == "Darwin":
        return home / "Library/Logs/Claude"
    return _app_support(home, system) / "Claude/logs"


def _home_mcp_sources(home: Path, system: str = "Darwin"):
    sup = _app_support(home, system)
    zed = sup / "Zed/settings.json" if system == "Windows" else home / ".config/zed/settings.json"
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
        ("Zed", zed),
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


SHORT_RANDOM = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]{12,}$")


UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _looks_secret(text: str) -> bool:
    if UUID.fullmatch(text) or UUID.fullmatch(text.split(".")[0]):
        return False  # standard random IDs (log file names, session IDs) are identifiers, not secrets
    if TOKEN_SHAPE.search(text):
        return True
    if RANDOM_SHAPE.match(text) and "/" not in text.strip("/") and not text.startswith("-"):
        return True
    # 12+ characters mixing letters and at least 3 digits, e.g. tunnel IDs and short tokens
    return bool(SHORT_RANDOM.match(text)) and sum(c.isdigit() for c in text) >= 3


def _safe(name):
    """Names are printed, so a name that is itself shaped like a token is redacted."""
    name = str(name)
    pieces = re.split(r"[_\s:=]", name) + re.findall(r"[A-Za-z0-9_\-+/=]{12,}", name)
    return "[redacted: looks like a secret]" if _looks_secret(name) or any(_looks_secret(p) for p in pieces) else name


_SAFE_PREFIX = None  # the scanned home folder: the user's own, never redacted


def _safe_path(path) -> str:
    """Locations are printed, so any folder or file name below the home folder shaped like a key is redacted."""
    text = str(path)
    prefix = ""
    if _SAFE_PREFIX and _SAFE_PREFIX in text:
        i = text.index(_SAFE_PREFIX) + len(_SAFE_PREFIX)
        prefix, text = text[:i], text[i:]
    parts = re.split(r"([/\\])", text)
    return prefix + "".join(p if p in ("/", "\\") or _safe(p) == p else "[redacted]" for p in parts)


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
        self.reach, self.unpinned, self.auto_agents = {}, set(), []
        self.home = None
        self._seen = set()

    def add(self, kind, name, where, **extra):
        where = _safe_path(where)
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
        args = cfg.get("args")
        if isinstance(cfg.get("command"), dict):
            args = cfg["command"].get("args", args)
        cmd = cfg.get("command")
        cmd_path = cmd.get("path") if isinstance(cmd, dict) else cmd
        one_word = isinstance(cmd_path, str) and len(cmd_path.split()) == 1  # "npx -y x" runs x, whatever args say
        env = cmd.get("env", cfg.get("env")) if isinstance(cmd, dict) else cfg.get("env")  # Zed keeps env in command
        plain = one_word and not isinstance(cfg.get("url"), str) and "envFile" not in cfg  # an env file can set a registry
        pkg = _package(target, args, env) if plain else None
        rep.add("mcp_server", _safe(name), where, runs=_safe(target), **({"package": pkg} if pkg else {}))
        rep.reach.setdefault(_capability(str(name), args), set()).add(_safe(name))
        if not isinstance(cfg.get("url"), str) and _unpinned(target, args):
            rep.unpinned.add(_safe(name))
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


# Windows install folder names (lowercase) and Linux .desktop file stems (lowercase) for each app.
WINDOWS_APP_DIRS = {"cursor": "Cursor", "anthropicclaude": "Claude", "claude": "Claude", "chatgpt": "ChatGPT",
                    "windsurf": "Windsurf", "ollama": "Ollama", "lm studio": "LM Studio", "lm-studio": "LM Studio",
                    "perplexity": "Perplexity", "jan": "Jan", "msty": "Msty", "zed": "Zed", "warp": "Warp",
                    "antigravity": "Antigravity", "granola": "Granola"}
LINUX_DESKTOP = {"cursor": "Cursor", "claude-desktop": "Claude", "claude": "Claude", "windsurf": "Windsurf",
                 "lm-studio": "LM Studio", "lmstudio": "LM Studio", "jan": "Jan", "msty": "Msty", "zed": "Zed",
                 "dev.zed.zed": "Zed", "warp": "Warp", "ollama": "Ollama", "antigravity": "Antigravity",
                 "chatgpt": "ChatGPT", "perplexity": "Perplexity"}
AI_CLIS = ["claude", "codex", "gemini", "ollama", "aider", "llm", "lms", "goose", "opencode", "amp", "cursor-agent", "qwen"]
CLOUD = [("AWS", (".aws",)), ("Azure", (".azure",)), ("Google Cloud", (".config/gcloud", "AppData/Roaming/gcloud"))]


def _scan_apps(apps_dir: Path, rep, home: Path, system: str):
    if system == "Darwin":
        for d in (apps_dir, home / "Applications"):
            if d.is_dir():
                present = {p.stem for p in d.glob("*.app")}
                for app in AI_APPS:
                    if app in present:
                        rep.add("ai_app", app, str(d / f"{app}.app"))
        return
    if system == "Windows":
        local = home / "AppData/Local"
        places = [local / "Programs", local, Path(os.environ.get("ProgramFiles", "C:/Program Files"))]
        for d in places:
            try:
                entries = [e for e in d.iterdir() if e.is_dir()]
            except OSError:
                continue
            for e in entries:
                app = WINDOWS_APP_DIRS.get(e.name.lower())
                if app:
                    rep.add("ai_app", app, str(e))
        return
    for d in (home / ".local/share/applications", Path("/usr/share/applications"),
              Path("/var/lib/flatpak/exports/share/applications"), Path("/var/lib/snapd/desktop/applications")):
        try:
            entries = list(d.glob("*.desktop"))
        except OSError:
            continue
        for e in entries:
            app = LINUX_DESKTOP.get(e.stem.lower())
            if app:
                rep.add("ai_app", app, str(e))


def _scan_clis(rep):
    """AI command-line tools on PATH. shutil.which only checks files; nothing is run."""
    for name in AI_CLIS:
        path = shutil.which(name)
        if path:
            rep.add("ai_cli", name, path)


def _scan_cloud(home: Path, rep):
    """Cloud accounts set up on this machine: existence of the config folder only. No file inside is read."""
    for label, rels in CLOUD:
        for rel in rels:
            if os.path.lexists(home / rel):
                rep.add("cloud_account", label, str(home / rel))
                break


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


def _scan_projects(roots, rep, home_sources=frozenset(), home_dir=None):
    seen_libs = set()
    for root in roots:
        if not root.is_dir():
            continue
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: rep.unreadable.append(str(e.filename))):
            d = Path(dirpath)
            dirnames[:] = sorted(n for n in dirnames if n not in SKIP_DIRS
                                 and (not n.startswith(".") or n in HIDDEN_ALLOWED)
                                 and not (n == "extensions" and d.name.startswith("."))  # editor extension bundles
                                 and not n.lower().endswith(MEDIA_SUFFIXES)
                                 and not (d == home_dir and n in MEDIA_TOP))
            filenames = sorted(filenames)
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


def _posture(home: Path, rep):
    """Agents set to act without asking: Claude Code bypass/allow-all, Codex never-ask with full disk access."""
    for path in (home / ".claude/settings.json", home / ".claude/settings.local.json"):
        try:
            data = json.loads(_read(path)) if path.exists() else {}
        except (_Unreadable, ValueError, RecursionError):
            rep.unreadable.append(str(path))
            continue
        perms = data.get("permissions") if isinstance(data, dict) and isinstance(data.get("permissions"), dict) else {}
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        if perms.get("defaultMode") == "bypassPermissions" or data.get("skipDangerousModePermissionPrompt") is True \
                or any(a in ("Bash", "Bash(*)", "Bash(:*)", "Bash(**)") for a in allow):
            rep.auto_agents.append(("Claude Code", str(path)))
            break
    codex = home / ".codex/config.toml"
    try:
        data = tomllib.loads(_read(codex)) if codex.exists() else {}
    except (_Unreadable, ValueError, RecursionError, tomllib.TOMLDecodeError):
        rep.unreadable.append(str(codex))
        data = {}
    if data.get("approval_policy") == "never" and data.get("sandbox_mode") == "danger-full-access":
        rep.auto_agents.append(("Codex", str(codex)))
    for agent, _ in rep.auto_agents:
        rep.reach.setdefault("run any command", set()).add(agent)


def _shell_path(path: str, home) -> str:
    """A paste-safe shell path: "$HOME"/'rest' under the home folder (same on every machine), else fully quoted."""
    if home:
        try:
            rel = Path(path).relative_to(home)
            return '"$HOME"/' + shlex.quote(rel.as_posix())
        except ValueError:
            pass
    return shlex.quote(path)


def _check(rep, rules):
    findings = []
    for agent, path in rep.auto_agents:
        findings.append({"rule": "agent-runs-without-asking", "subject": agent, "where": path,
                         "why": "This AI agent runs commands and changes files without asking first. One bad prompt or "
                                "poisoned web page can act with your full access. Turn approvals back on."})
    for server in sorted(rep.unpinned):
        findings.append({"rule": "unpinned-mcp-server", "subject": server,
                         "why": "This MCP server downloads its latest code every time it starts. Pin an exact version "
                                "so new code can't arrive unreviewed."})
    for key, path in rep.exposed_keys:
        path = _safe_path(path)
        findings.append({"rule": "plaintext-ai-key-in-repo", "subject": key, "where": path,
                         "why": "An AI key is stored in plain text inside a git repository. Confirm it can never be "
                                f"committed: git check-ignore -v {_shell_path(path, rep.home)} must print a rule, and "
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
            if item["kind"] in ("api_key", "cloud_account"):
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


def scan(home, apps_dir=Path("/Applications"), roots=None, rules=None, with_activity=True, days=30, system=None):
    home = Path(home)
    rules = validate_rules(rules)
    roots = [Path(r) for r in (roots or [home])]
    system = system or os.environ.get("XOVA_SCAN_SYSTEM") or platform.system()  # env pin is for tests
    global _SAFE_PREFIX
    _SAFE_PREFIX = str(home)
    rep = _Report()
    rep.home = home
    sources = _home_mcp_sources(home, system)
    for client, path in sources:
        if path.exists():
            _scan_mcp_file(client, path, rep)
    _scan_apps(Path(apps_dir), rep, home, system)
    _scan_clis(rep)
    _scan_cloud(home, rep)
    _scan_projects(roots, rep, {p for _, p in sources}, home)
    _posture(home, rep)
    act = None
    if with_activity:
        from .activity import activity
        act = activity(home, TOKEN_SHAPE, days=days, unreadable=rep.unreadable,
                       desktop_logs=claude_desktop_logs(home, system))
    findings = _check(rep, rules)
    if act and act["secrets_in_logs"]:
        files = act["secret_log_files"] = [_safe_path(f) for f in act["secret_log_files"]]
        findings.insert(0, {"rule": "secret-in-ai-logs", "subject": f"{act['secrets_in_logs']} unique keys or tokens in {len(files)} AI log files",
                            "where": ", ".join(files[:3]) + (f" and {len(files) - 3} more" if len(files) > 3 else ""),
                            "why": "Strings shaped like real keys or tokens (OpenAI/Anthropic sk-, GitHub, Slack, Google, GitLab, AWS, Stripe, "
                                   "JWT; obvious test values excluded) were pasted into or "
                                   "printed in AI chats, and the agent kept a copy in its local logs. Check them, rotate any real "
                                   "key, and clear old logs."})
    # Deterministic output: one canonical order, independent of how the file system lists things.
    kinds = ["mcp_server", "ai_app", "ai_cli", "ai_library", "api_key", "cloud_account"]
    rep.found.sort(key=lambda f: (kinds.index(f["kind"]) if f["kind"] in kinds else 99, f["name"], f["where"]))
    findings.sort(key=lambda f: (f["rule"], f["subject"], f.get("where", "")))
    rep.unreadable = sorted({_safe_path(u) for u in rep.unreadable})
    return {"tool": "xova-scan", "version": __version__, "note": NOTE, "found": rep.found,
            "reach": {k: sorted(v) for k, v in sorted(rep.reach.items())},
            "activity": act, "findings": findings, "unreadable": rep.unreadable, "roots": [str(r) for r in roots]}
