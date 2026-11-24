"""MCP package identity: what a server actually runs from a public registry, so XOVA can match by package, not by label."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from xova_scan import _package, scan
from xova_scan.export import to_xova

os.environ["XOVA_SCAN_SYSTEM"] = "Darwin"


class PackageIdentityTests(unittest.TestCase):
    def test_npm_runners_with_and_without_versions(self):
        cases = [
            ("npx", ["-y", "@playwright/mcp@latest"], "npm:@playwright/mcp"),
            ("npx", ["@modelcontextprotocol/server-postgres@0.6.2", "postgres://x"], "npm:@modelcontextprotocol/server-postgres"),
            ("bunx", ["mcp-remote"], "npm:mcp-remote"),
            ("pnpx", ["--yes", "some-server@1.2.3"], "npm:some-server"),
        ]
        for program, args, want in cases:
            self.assertEqual(_package(program, args), want, (program, args))

    def test_python_runners_normalised(self):
        self.assertEqual(_package("uvx", ["mcp-server-fetch"]), "pypi:mcp-server-fetch")
        self.assertEqual(_package("uvx", ["Mcp_Server.Git==1.0"]), "pypi:mcp-server-git")
        self.assertEqual(_package("uvx", ["awslabs.core-mcp-server@latest"]), "pypi:awslabs-core-mcp-server")
        self.assertEqual(_package("pipx", ["run", "mcp-server-time"]), "pypi:mcp-server-time")
        self.assertEqual(_package("uvx", ["mcp-x[cli]>=2"]), "pypi:mcp-x")

    def test_unknown_or_ambiguous_gives_no_identity(self):
        # Never guess: anything not a plain registry package from a known runner has no identity.
        for program, args in [
            ("node", ["server.js"]), ("python", ["-m", "srv"]), ("docker", ["run", "mcp/postgres"]),
            ("npx", []), ("npx", "not-a-list"), ("npx", ["./local-server"]), ("npx", ["/abs/srv"]),
            ("npx", ["file:../srv"]), ("npx", ["github:user/repo"]), ("npx", ["git+https://h/r.git"]),
            ("npx", ["https://h/pkg.tgz"]), ("npx", ["--package=a", "b"]), ("npx", ["-p", "a", "b"]),
            ("uvx", ["--from", "pkg", "cmd"]), ("uvx", ["git+https://h/r"]), ("pipx", ["install", "x"]),
            ("npx", ["UPPER-Case"]), ("npx", ["@scope"]), ("npx", ["a" * 215]), ("npx", [5, None]),
        ]:
            self.assertIsNone(_package(program, args), (program, args))

    def test_secret_shaped_package_is_never_emitted(self):
        self.assertIsNone(_package("npx", ["sk-live-THIS-MUST-NEVER-APPEAR-123"]))

    def test_scan_reports_package_on_mcp_findings(self):
        with tempfile.TemporaryDirectory() as t:
            home = Path(t) / "home"
            cfg = home / ".cursor/mcp.json"
            cfg.parent.mkdir(parents=True)
            cfg.write_text(json.dumps({"mcpServers": {
                "playwright": {"command": "npx", "args": ["-y", "@playwright/mcp@latest"]},
                "mine": {"command": "node", "args": ["/srv/index.js"]},
                "remote": {"url": "https://mcp.example/sse"}}}))
            (Path(t) / "Apps").mkdir()
            r = scan(home=home, apps_dir=Path(t) / "Apps", roots=[])
        pkg = {f["name"]: f.get("package") for f in r["found"] if f["kind"] == "mcp_server"}
        self.assertEqual(pkg, {"playwright": "npm:@playwright/mcp", "mine": None, "remote": None})

    def test_export_note_names_the_package_for_humans(self):
        rep = {"version": "0.5.0", "found": [
            {"kind": "mcp_server", "name": "playwright", "where": "Cursor (~/.cursor/mcp.json)", "runs": "npx",
             "package": "npm:@playwright/mcp"},
            {"kind": "mcp_server", "name": "mine", "where": "Cursor (~/.cursor/mcp.json)", "runs": "node"}]}
        entries = to_xova(rep, team="eng", added_on="2026-11-24", machine="m")[0]["entries"]
        notes = {e["tool_name"]: e["discovery_note"] for e in entries}
        self.assertIn("Package: npm:@playwright/mcp.", notes["playwright"])
        self.assertNotIn("Package:", notes["mine"])


if __name__ == "__main__":
    unittest.main()
