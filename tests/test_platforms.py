"""v0.3: the same scan on Windows and Linux layouts, AI command-line tools, and the cloud hint."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xova_scan import scan


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


SERVERS = json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.0.0"]}}})
LOG = '2026-11-20T10:00:00Z [webflow] [info] Message from client: {"method":"tools/call","params":{}}\n'


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def names(self, r, kind):
        return sorted(f["name"] for f in r["found"] if f["kind"] == kind)

    def test_windows_layout(self):
        roaming, local = self.home / "AppData/Roaming", self.home / "AppData/Local"
        write(roaming / "Claude/claude_desktop_config.json", SERVERS)
        write(roaming / "Code/User/mcp.json", json.dumps({"servers": {"vs": {"command": "npx", "args": ["x@1.0.0"]}}}))
        write(roaming / "Claude/logs/mcp-server-webflow.log", LOG)
        (local / "Programs/cursor").mkdir(parents=True)
        (local / "AnthropicClaude").mkdir(parents=True)
        (local / "Programs/Ollama").mkdir(parents=True)
        r = scan(home=self.home, roots=[self.home / "nocode"], system="Windows")
        self.assertEqual(self.names(r, "mcp_server"), ["github", "vs"])
        self.assertEqual(self.names(r, "ai_app"), ["Claude", "Cursor", "Ollama"])
        self.assertEqual(r["activity"]["mcp_tool_calls"].get("webflow (Claude Desktop)"), 1)

    def test_linux_layout(self):
        cfg = self.home / ".config"
        write(cfg / "Claude/claude_desktop_config.json", SERVERS)
        write(cfg / "Code/User/settings.json", json.dumps({"mcp": {"servers": {"vs": {"command": "npx", "args": ["x@1.0.0"]}}}}))
        write(self.home / ".local/share/applications/cursor.desktop", "[Desktop Entry]\nName=Cursor\n")
        write(self.home / ".local/share/applications/lm-studio.desktop", "[Desktop Entry]\nName=LM Studio\n")
        r = scan(home=self.home, roots=[self.home / "nocode"], system="Linux")
        self.assertEqual(self.names(r, "mcp_server"), ["github", "vs"])
        self.assertEqual(self.names(r, "ai_app"), ["Cursor", "LM Studio"])

    def test_ai_command_line_tools_on_path(self):
        fake = {"claude": "/usr/local/bin/claude", "ollama": "/usr/local/bin/ollama"}
        with mock.patch("shutil.which", side_effect=lambda n: fake.get(n)):
            r = scan(home=self.home, roots=[self.home / "nocode"], system="Linux", with_activity=False)
        self.assertEqual(self.names(r, "ai_cli"), ["claude", "ollama"])

    def test_cloud_accounts_are_hinted_not_read(self):
        write(self.home / ".aws/credentials", "[default]\naws_secret_access_key = SHOULD-NEVER-APPEAR\n")
        (self.home / ".azure").mkdir()
        (self.home / ".config/gcloud").mkdir(parents=True)
        r = scan(home=self.home, roots=[self.home / "nocode"], system="Linux", with_activity=False)
        self.assertEqual(self.names(r, "cloud_account"), ["AWS", "Azure", "Google Cloud"])
        self.assertNotIn("SHOULD-NEVER-APPEAR", json.dumps(r))


if __name__ == "__main__":
    unittest.main()
