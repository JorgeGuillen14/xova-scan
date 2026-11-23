import io
import os
import subprocess
import threading
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from xova_scan import scan
from xova_scan.cli import main

SECRET = "sk-live-THIS-MUST-NEVER-APPEAR-123"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class Machine:
    """A fake home directory with AI in every place the scanner looks."""

    def __init__(self, tmp: Path):
        self.home = tmp / "home"
        self.apps = tmp / "Applications"
        (self.apps / "Claude.app").mkdir(parents=True)
        (self.apps / "Cursor.app").mkdir()
        (self.apps / "Keynote.app").mkdir()
        write(self.home / "Library/Application Support/Claude/claude_desktop_config.json",
              json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                                                    "env": {"GITHUB_TOKEN": SECRET}}}}))
        write(self.home / ".cursor/mcp.json", json.dumps({"mcpServers": {"postgres": {"command": "uvx", "args": ["mcp-postgres"]}}}))
        write(self.home / ".claude.json", json.dumps({"mcpServers": {"filesystem": {"command": "npx"}},
                                                      "projects": {"/x": {"mcpServers": {"slack": {"url": "https://mcp.example/slack"}}}}}))
        app = self.home / "code/shop"
        write(app / "package.json", json.dumps({"dependencies": {"openai": "^5.0.0", "react": "18"}, "devDependencies": {"@anthropic-ai/sdk": "1"}}))
        write(app / ".env", f"OPENAI_API_KEY={SECRET}\nDATABASE_URL=postgres://x\n")
        subprocess.run(["git", "init", "-q", str(app)], check=True)
        api = self.home / "code/api"
        write(api / "requirements.txt", "langchain==0.3\nrequests\n")
        write(api / "pyproject.toml", '[project]\ndependencies = ["anthropic>=0.40", "fastapi"]\n')
        write(api / ".env", f"ANTHROPIC_API_KEY={SECRET}\n")
        write(api / ".gitignore", ".env\n")
        subprocess.run(["git", "init", "-q", str(api)], check=True)
        write(self.home / "code/shop/node_modules/openai/package.json", json.dumps({"dependencies": {"ollama": "1"}}))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.m = Machine(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def run_scan(self, rules=None):
        return scan(home=self.m.home, apps_dir=self.m.apps, roots=[self.m.home / "code"], rules=rules)

    def names(self, report, kind):
        return sorted(f["name"] for f in report["found"] if f["kind"] == kind)

    def test_finds_mcp_servers_in_every_client(self):
        r = self.run_scan()
        self.assertEqual(self.names(r, "mcp_server"), ["filesystem", "github", "postgres", "slack"])
        clients = {f["name"]: f["where"] for f in r["found"] if f["kind"] == "mcp_server"}
        self.assertIn("Claude Desktop", clients["github"])
        self.assertIn("Cursor", clients["postgres"])

    def test_finds_installed_ai_apps_only(self):
        self.assertEqual(self.names(self.run_scan(), "ai_app"), ["Claude", "Cursor"])

    def test_finds_ai_libraries_in_projects_and_skips_node_modules(self):
        libs = self.names(self.run_scan(), "ai_library")
        self.assertEqual(libs, ["@anthropic-ai/sdk", "anthropic", "langchain", "openai"])

    def test_finds_api_key_names(self):
        self.assertEqual(self.names(self.run_scan(), "api_key"), ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"])

    def test_secret_values_never_appear_anywhere(self):
        r = self.run_scan()
        self.assertNotIn(SECRET, json.dumps(r))
        out = io.StringIO()
        with redirect_stdout(out):
            main(["--home", str(self.m.home), "--apps", str(self.m.apps), str(self.m.home / "code")])
        self.assertNotIn(SECRET, out.getvalue())

    def test_never_uses_the_network(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network used")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")):
            self.run_scan()

    def test_everything_is_not_reviewed_by_default(self):
        r = self.run_scan()
        self.assertTrue(all(f["status"] == "Not reviewed" for f in r["found"]))

    def test_rule_key_in_unignored_env_file(self):
        hit = [f for f in self.run_scan()["findings"] if f["rule"] == "no-plaintext-keys-in-git"]
        self.assertEqual([f["subject"] for f in hit], ["OPENAI_API_KEY"])  # api/.env is git-ignored

    def test_rule_secret_inline_in_mcp_config(self):
        hit = [f["subject"] for f in self.run_scan()["findings"] if f["rule"] == "no-secrets-in-mcp-config"]
        self.assertEqual(hit, ["github"])

    def test_rule_approved_tools_only(self):
        rules = {"approved": ["Claude", "openai", "github", "filesystem"]}
        hit = sorted(f["subject"] for f in self.run_scan(rules)["findings"] if f["rule"] == "approved-tools-only")
        self.assertEqual(hit, ["@anthropic-ai/sdk", "Cursor", "anthropic", "langchain", "postgres", "slack"])
        approved = [f for f in self.run_scan(rules)["found"] if f["name"] == "Claude"]
        self.assertEqual(approved[0]["status"], "Approved")

    def test_approved_rule_off_when_no_list(self):
        self.assertFalse([f for f in self.run_scan()["findings"] if f["rule"] == "approved-tools-only"])

    def test_broken_config_is_reported_not_crashed(self):
        write(self.m.home / ".cursor/mcp.json", "{not json")
        r = self.run_scan()
        self.assertTrue(any("Cursor" in s for s in r["unreadable"]))

    def test_json_output(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--json", "--home", str(self.m.home), "--apps", str(self.m.apps), str(self.m.home / "code")])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertIn("found", data)
        self.assertIn("note", data)


class HostileInputTests(unittest.TestCase):
    """Review findings 1-11: leaks, crashes, hangs, false safe verdicts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.code = self.home / "code"
        self.code.mkdir(parents=True)
        self.apps = self.root / "Applications"
        self.apps.mkdir()

    def tearDown(self):
        os.system(f"chmod -R u+rwx {self.root}")
        self.tmp.cleanup()

    def run_scan(self, rules=None):
        return scan(home=self.home, apps_dir=self.apps, roots=[self.code], rules=rules)

    def cursor(self, servers):
        write(self.home / ".cursor/mcp.json", json.dumps({"mcpServers": servers}))

    def test_url_args_command_and_header_tokens_never_leak(self):
        self.cursor({"urltok": {"url": "https://user:LEAK0@mcp.x/sse?api_key=LEAK1"},
                     "argtok": {"command": "npx", "args": ["srv", "--token=LEAK2", "--api-key", "LEAK5"]},
                     "cmdtok": {"command": "LEAK3=1 /usr/local/bin/npx"},
                     "xkey": {"url": "https://h", "headers": {"X-API-Key": "LEAK4"}}})
        r = self.run_scan()
        self.assertNotIn("LEAK", json.dumps(r))
        flagged = sorted(f["subject"] for f in r["findings"] if f["rule"] == "no-secrets-in-mcp-config")
        self.assertEqual(flagged, ["argtok", "urltok", "xkey"])
        keys = [f["name"] for f in r["found"] if f["kind"] == "api_key"]
        self.assertIn("X-API-Key", keys)
        runs = {f["name"]: f["runs"] for f in r["found"] if f["kind"] == "mcp_server"}
        self.assertEqual(runs["urltok"], "https://mcp.x")
        self.assertEqual(runs["argtok"], "npx")

    def test_malformed_files_are_recorded_not_crashed(self):
        write(self.code / "a/package.json", "[]")
        write(self.code / "b/pyproject.toml", 'project = "x"\n')
        self.cursor({"bad1": {"args": 5}, "bad2": {"url": {"a": 1}}, "ok": {"command": "uvx"}})
        r = self.run_scan()
        self.assertIn("ok", [f["name"] for f in r["found"] if f["kind"] == "mcp_server"])
        self.assertTrue(any("package.json" in u for u in r["unreadable"]))

    def test_fifo_and_device_symlinks_do_not_hang(self):
        (self.code / "f").mkdir()
        os.mkfifo(self.code / "f/.env")
        os.symlink("/dev/zero", self.code / "f/requirements.txt")
        done = []
        t = threading.Thread(target=lambda: done.append(self.run_scan()), daemon=True)
        t.start(); t.join(5)
        self.assertTrue(done, "scan hung")

    def git_repo(self, path):
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(path)], check=True)

    def test_gitignore_star_env_does_not_hide_prod_env(self):
        self.git_repo(self.code / "r")
        write(self.code / "r/.gitignore", ".env*\n")
        write(self.code / "r/prod.env", "OPENAI_API_KEY=x\n")
        hit = [f["where"] for f in self.run_scan()["findings"] if f["rule"] == "no-plaintext-keys-in-git"]
        self.assertTrue(any(h.endswith("prod.env") for h in hit))

    def test_gitignore_negation_is_respected(self):
        self.git_repo(self.code / "n")
        write(self.code / "n/.gitignore", ".env\n!.env\n")
        write(self.code / "n/.env", "OPENAI_API_KEY=x\n")
        self.assertTrue([f for f in self.run_scan()["findings"] if f["rule"] == "no-plaintext-keys-in-git"])

    def test_env_in_subfolder_of_repo_is_checked(self):
        self.git_repo(self.code / "b")
        write(self.code / "b/sub/.env", "OPENAI_API_KEY=x\n")
        self.assertTrue([f for f in self.run_scan()["findings"] if f["rule"] == "no-plaintext-keys-in-git"])

    def test_env_example_templates_are_not_flagged(self):
        self.git_repo(self.code / "t")
        write(self.code / "t/.env.example", "OPENAI_API_KEY=\n")
        write(self.code / "t/.env.sample", "OPENAI_API_KEY=\n")
        self.assertFalse([f for f in self.run_scan()["findings"] if f["rule"] == "no-plaintext-keys-in-git"])

    def test_more_mcp_locations(self):
        write(self.code / "p/.mcp.json", json.dumps({"mcpServers": {"projsrv": {"command": "npx"}}}))
        write(self.code / "p/.vscode/mcp.json", json.dumps({"servers": {"vssrv": {"command": "npx"}}}))
        write(self.code / "p/.cursor/mcp.json", json.dumps({"mcpServers": {"cursrv": {"command": "npx"}}}))
        write(self.home / ".codex/config.toml", '[mcp_servers.codexsrv]\ncommand = "npx"\n')
        write(self.home / ".config/zed/settings.json", json.dumps({"context_servers": {"zedsrv": {"command": {"path": "npx"}}}}))
        write(self.home / ".lmstudio/mcp.json", json.dumps({"mcpServers": {"lmsrv": {"command": "npx"}}}))
        names = sorted(f["name"] for f in self.run_scan()["found"] if f["kind"] == "mcp_server")
        self.assertEqual(names, ["codexsrv", "cursrv", "lmsrv", "projsrv", "vssrv", "zedsrv"])

    def test_no_duplicates(self):
        write(self.home / ".claude.json", json.dumps({"projects": {"/a": {"mcpServers": {"s": {"command": "npx"}}},
                                                                   "/b": {"mcpServers": {"s": {"command": "npx"}}}}}))
        self.cursor({"k": {"command": "npx", "env": {"OPENAI_API_KEY": "v"}, "headers": {"OPENAI_API_KEY": "v"}}})
        r = self.run_scan()
        self.assertEqual([f["name"] for f in r["found"] if f["kind"] == "mcp_server"].count("s"), 1)
        self.assertEqual([f["name"] for f in r["found"] if f["kind"] == "api_key"].count("OPENAI_API_KEY"), 1)

    def test_unreadable_folder_is_listed(self):
        locked = self.code / "locked"
        locked.mkdir()
        os.chmod(locked, 0)
        self.assertTrue(any("locked" in u for u in self.run_scan()["unreadable"]))

    def test_bad_rules_file_exits_cleanly(self):
        bad = self.root / "rules.json"
        bad.write_text("[1]")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                main(["--rules", str(bad), "--home", str(self.home), "--apps", str(self.apps), str(self.code)])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
