"""A reproducible demo machine for xova-scan.

Builds a small fake home folder (macOS layout) with AI tools configured, then the README
shows the scanner's real output on it. Nothing here is a real person's data.

    python3 examples/demo_machine.py            # build in a temp folder and print the scan
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run from a source checkout


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _tool(name, inp):
    return json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name, "input": inp}]}})


def build(root: Path) -> Path:
    home = Path(root) / "demo-home"
    for app in ("Claude", "Cursor", "Keynote"):
        (home / "Applications" / f"{app}.app").mkdir(parents=True, exist_ok=True)
    _write(home / "Library/Application Support/Claude/claude_desktop_config.json", json.dumps({"mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "~/Documents"]},
        "playwright": {"command": "npx", "args": ["@playwright/mcp@latest"]},
    }}, indent=2))
    _write(home / ".cursor/mcp.json", json.dumps({"mcpServers": {
        "supabase": {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase"],
                     "env": {"SUPABASE_ACCESS_TOKEN": "pasted-token-goes-here"}},
    }}, indent=2))
    _write(home / ".codex/config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    app = home / "code/shop"
    _write(app / "package.json", json.dumps({"dependencies": {"openai": "^5.0.0", "next": "15.0.0"}}))
    _write(app / ".env", "OPENAI_API_KEY=placeholder\n")
    (app / ".git").mkdir(parents=True, exist_ok=True)
    _write(home / "code/api/requirements.txt", "anthropic==0.40.0\nfastapi\n")
    _write(home / ".claude/projects/-demo-home-code-shop/session.jsonl", "\n".join([
        _tool("Bash", {"command": "git status"}),
        _tool("Bash", {"command": "npm test"}),
        _tool("Bash", {"command": "rm -rf .next && npm run build"}),
        _tool("Bash", {"command": "git push --force origin main"}),
        _tool("Edit", {"file_path": str(app / "app/page.tsx")}),
        _tool("Edit", {"file_path": str(app / "lib/ai.ts")}),
        _tool("WebFetch", {"url": "https://platform.openai.com/docs"}),
        _tool("mcp__supabase__execute_sql", {"query": "select 1"}),
    ]) + "\n")
    return home


def demo_output() -> str:
    """The scanner's real terminal output on the demo machine."""
    import io
    import os
    from contextlib import redirect_stdout
    from unittest import mock
    from xova_scan.cli import main as cli_main
    with tempfile.TemporaryDirectory() as tmp:
        home = build(Path(tmp))
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"XOVA_SCAN_SYSTEM": "Darwin"}), \
             mock.patch("shutil.which", return_value=None), redirect_stdout(out):
            cli_main(["--home", str(home), "--apps", str(home / "Applications")])
        return out.getvalue()


START, END = "<!-- demo-output-start -->", "<!-- demo-output-end -->"


def update_readme(readme: Path):
    text = readme.read_text()
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    readme.write_text(head + START + "\n```\n" + demo_output() + "```\n" + END + tail)


def main():
    if "--update-readme" in sys.argv:
        update_readme(Path(__file__).resolve().parent.parent / "README.md")
        print("README demo output regenerated")
    else:
        sys.stdout.write(demo_output())


if __name__ == "__main__":
    main()
