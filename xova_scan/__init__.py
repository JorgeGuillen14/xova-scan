"""xova-scan: find the AI on this machine and check it against your rules.

Runs locally. Never opens a network connection. Never reads, stores or prints a
secret's value: only the name of the variable or config key that holds it.
"""
import json
import os
import re
import tomllib
from pathlib import Path

__version__ = "0.1.0"

NOTE = ("Local scan only. Nothing left this machine. Secret values were never read into the report. "
        "Finding nothing does not prove there is no AI here.")

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
    "mcp", "@modelcontextprotocol/sdk", "fastmcp", "boto3-bedrock", "@aws-sdk/client-bedrock-runtime",
    "azure-ai-openai", "@azure/openai", "openai-agents", "@openai/agents", "smolagents", "haystack-ai",
}

KEY_NAME = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]*(?:API_KEY|_TOKEN|_SECRET|_KEY))\s*=")
AI_KEY_HINT = re.compile(r"OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_API|MISTRAL|COHERE|GROQ|TOGETHER|REPLICATE|"
                         r"HUGGINGFACE|HF_|PERPLEXITY|XAI|DEEPSEEK|AZURE_OPENAI|BEDROCK|OPENROUTER|LANGCHAIN|"
                         r"LANGSMITH|PINECONE|ELEVENLABS|FIREWORKS|VOYAGE")

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "site-packages", "dist", "build",
             ".next", ".cache", "Library", ".Trash", "Applications", ".npm", ".cargo", ".rustup", "Pods"}
MAX_DEPTH = 6


def _mcp_sources(home: Path):
    sup = home / "Library/Application Support"
    return [
        ("Claude Desktop", sup / "Claude/claude_desktop_config.json"),
        ("Claude Code", home / ".claude.json"),
        ("Cursor", home / ".cursor/mcp.json"),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json"),
        ("VS Code", sup / "Code/User/mcp.json"),
        ("VS Code", sup / "Code/User/settings.json"),
        ("Gemini CLI", home / ".gemini/settings.json"),
    ]


def _servers(data):
    """Yield (name, config) from every place a client keeps MCP servers."""
    if not isinstance(data, dict):
        return
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            yield from ((n, c) for n, c in block.items() if isinstance(c, dict))
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        yield from _servers(mcp)
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            yield from _servers(proj)


def _found(kind, name, where, **extra):
    return {"kind": kind, "name": name, "where": where, "status": "Not reviewed", **extra}


def _scan_mcp(home, found, unreadable, inline_secrets):
    for client, path in _mcp_sources(home):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            unreadable.append(f"{client}: {path}")
            continue
        for name, cfg in _servers(data):
            target = cfg.get("url") or " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", [])][:3])
            found.append(_found("mcp_server", name, f"{client} ({path})", runs=target.strip()))
            env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
            headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
            for key in list(env) + list(headers):
                # Only the key name is kept. A non-empty literal (not a ${VAR} reference) means a secret sits in the file.
                val = env.get(key, headers.get(key))
                literal = isinstance(val, str) and val.strip() and not val.strip().startswith("${")
                if KEY_NAME.match(f"{key}=") or "TOKEN" in key.upper() or "AUTH" in key.upper():
                    found.append(_found("api_key", key, f"{client} config for MCP server '{name}'"))
                    if literal:
                        inline_secrets.append(name)


def _scan_apps(apps_dir, found):
    if not apps_dir.is_dir():
        return
    present = {p.stem for p in apps_dir.glob("*.app")}
    for app in AI_APPS:
        if app in present:
            found.append(_found("ai_app", app, str(apps_dir / f"{app}.app")))


def _deps_from(path: Path):
    name = path.name
    text = path.read_text(errors="ignore")
    if name == "package.json":
        data = json.loads(text)
        deps = {}
        for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if isinstance(data.get(k), dict):
                deps.update(data[k])
        return list(deps)
    if name == "pyproject.toml":
        data = tomllib.loads(text)
        reqs = list(data.get("project", {}).get("dependencies", []))
        for group in data.get("project", {}).get("optional-dependencies", {}).values():
            reqs += group
        reqs += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}))
        return [re.split(r"[\s<>=!~\[;]", r.strip(), maxsplit=1)[0] for r in reqs if isinstance(r, str)]
    # requirements*.txt
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            out.append(re.split(r"[\s<>=!~\[;]", line, maxsplit=1)[0])
    return out


def _walk(root: Path):
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".config",))]
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        yield Path(dirpath), filenames


def _ignored_by_git(project: Path, filename: str) -> bool:
    gi = project / ".gitignore"
    if not gi.is_file():
        return False
    patterns = [l.strip() for l in gi.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
    return any(p.lstrip("/") in (filename, ".env*", "*.env", ".env.*") or p.lstrip("/") == filename for p in patterns)


def _key_names(path: Path):
    """Return variable names that look like keys. The value side of each line is never kept."""
    names = []
    try:
        with path.open(errors="ignore") as fh:
            for line in fh:
                m = KEY_NAME.match(line.strip())
                if m:
                    names.append(m.group(1))
    except OSError:
        pass
    return names


def _scan_projects(roots, found, unreadable, exposed_keys):
    seen_libs = set()
    for root in roots:
        if not root.is_dir():
            continue
        for d, files in _walk(root):
            is_git = (d / ".git").exists()
            for f in files:
                p = d / f
                if f in ("package.json", "pyproject.toml") or (f.startswith("requirements") and f.endswith(".txt")):
                    try:
                        deps = _deps_from(p)
                    except (OSError, ValueError, tomllib.TOMLDecodeError):
                        unreadable.append(str(p))
                        continue
                    for dep in deps:
                        if dep.lower() in AI_LIBRARIES and (dep.lower(), str(d)) not in seen_libs:
                            seen_libs.add((dep.lower(), str(d)))
                            found.append(_found("ai_library", dep.lower(), str(p)))
                elif f == ".env" or f.startswith(".env.") or f.endswith(".env"):
                    for key in _key_names(p):
                        if AI_KEY_HINT.search(key):
                            found.append(_found("api_key", key, str(p)))
                            if is_git and not _ignored_by_git(d, f):
                                exposed_keys.append((key, str(p)))


def _check(found, rules, inline_secrets, exposed_keys):
    findings = []
    for key, path in exposed_keys:
        findings.append({"rule": "no-plaintext-keys-in-git", "subject": key, "where": path,
                         "why": "An AI key sits in a file that git does not ignore, so it can be committed."})
    for server in sorted(set(inline_secrets)):
        findings.append({"rule": "no-secrets-in-mcp-config", "subject": server,
                         "why": "This MCP server's config holds a secret in plain text. Use an environment variable reference."})
    approved = {a.lower() for a in rules.get("approved", [])}
    if approved:
        for item in found:
            if item["kind"] == "api_key":
                continue
            if item["name"].lower() in approved:
                item["status"] = "Approved"
            else:
                findings.append({"rule": "approved-tools-only", "subject": item["name"], "where": item["where"],
                                 "why": "Not on your approved list."})
    return findings


def scan(home, apps_dir=Path("/Applications"), roots=None, rules=None):
    home = Path(home)
    rules = rules or {}
    roots = [Path(r) for r in (roots or [home])]
    found, unreadable, inline_secrets, exposed_keys = [], [], [], []
    _scan_mcp(home, found, unreadable, inline_secrets)
    _scan_apps(Path(apps_dir), found)
    _scan_projects(roots, found, unreadable, exposed_keys)
    findings = _check(found, rules, inline_secrets, exposed_keys)
    return {"tool": "xova-scan", "version": __version__, "note": NOTE, "found": found,
            "findings": findings, "unreadable": unreadable, "roots": [str(r) for r in roots]}
