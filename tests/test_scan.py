import io
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
        (app / ".git").mkdir()
        api = self.home / "code/api"
        write(api / "requirements.txt", "langchain==0.3\nrequests\n")
        write(api / "pyproject.toml", '[project]\ndependencies = ["anthropic>=0.40", "fastapi"]\n')
        write(api / ".env", f"ANTHROPIC_API_KEY={SECRET}\n")
        write(api / ".gitignore", ".env\n")
        (api / ".git").mkdir()
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


if __name__ == "__main__":
    unittest.main()
