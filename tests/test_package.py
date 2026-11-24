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

    def test_review_flags_with_values_never_become_the_package(self):
        for program, args in [
            ("npx", ["--call", "evil-cmd"]), ("npx", ["--registry", "evil", "x"]), ("npx", ["-yp", "@evil/x", "@playwright/mcp"]),
            ("bunx", ["--registry", "evil", "@playwright/mcp"]), ("bunx", ["--cwd", "x", "@playwright/mcp"]),
            ("pnpx", ["--filter", "foo", "@playwright/mcp"]), ("pnpx", ["-C", "foo", "@playwright/mcp"]),
            ("pnpx", ["--allow-build", "esbuild", "@playwright/mcp"]),
            ("uvx", ["--with", "evil", "mcp-server-fetch"]), ("uvx", ["-w", "evil", "mcp-server-fetch"]),
            ("uvx", ["--python", "3.12", "mcp-server-fetch"]), ("uvx", ["--with-requirements", "r.txt", "x"]),
            ("pipx", ["run", "--spec", "evil", "mcp-server-fetch"]), ("pipx", ["run", "--spec=evil", "mcp-server-fetch"]),
            ("pipx", ["run", "--python", "3.12", "mcp-server-fetch"]),
        ]:
            self.assertIsNone(_package(program, args), (program, args))

    def test_review_non_registry_sources_in_the_version_part(self):
        for program, args in [
            ("npx", ["pkg@https://evil/x.tgz"]), ("npx", ["pkg@file:../x"]), ("npx", ["pkg@github:evil/x"]),
            ("npx", ["pkg@evil/x"]), ("npx", ["evil@npm:@playwright/mcp"]),
            ("uvx", ["mcp-server-fetch @ https://evil/x.whl"]), ("uvx", ["mcp-server-fetch@https://evil"]),
            ("npx", ["mcp.tgz"]), ("uvx", ["x.whl"]), ("pipx", ["run", "script.py"]), ("npx", ["x.tar.gz"]),
        ]:
            self.assertIsNone(_package(program, args), (program, args))
        self.assertEqual(_package("npx", ["--", "pkg@^1.2.0"]), "npm:pkg")
        self.assertEqual(_package("npx", ["chart.js@4"]), "npm:chart.js")

    def test_review_registry_override_in_env_gives_none(self):
        for key in ["npm_config_registry", "NPM_CONFIG_REGISTRY", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX",
                    "UV_EXTRA_INDEX_URL", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"]:
            self.assertIsNone(_package("npx", ["@playwright/mcp"], env={key: "https://evil.example"}), key)
        self.assertEqual(_package("npx", ["@playwright/mcp"], env={"DEBUG": "1"}), "npm:@playwright/mcp")

    def test_review_command_string_with_arguments_gives_none(self):
        with tempfile.TemporaryDirectory() as t:
            home = Path(t) / "home"
            cfg = home / ".cursor/mcp.json"
            cfg.parent.mkdir(parents=True)
            cfg.write_text(json.dumps({"mcpServers": {
                "shell": {"command": "npx -y evil-pkg", "args": ["@playwright/mcp"]},
                "zed": {"command": {"path": "npx -y evil", "args": ["@playwright/mcp"]}},
                "envreg": {"command": "npx", "args": ["@playwright/mcp"], "env": {"npm_config_registry": "https://e"}}}}))
            (Path(t) / "Apps").mkdir()
            r = scan(home=home, apps_dir=Path(t) / "Apps", roots=[])
        self.assertEqual([f.get("package") for f in r["found"] if f["kind"] == "mcp_server"], [None, None, None])

    def test_review_long_location_never_truncates_the_package(self):
        for n in range(400, 620, 3):
            rep = {"version": "0.5.0", "found": [{"kind": "mcp_server", "name": "p", "where": "d/" * n, "runs": "npx",
                                                  "package": "npm:@playwright/mcp"}]}
            note = to_xova(rep, team="eng", added_on="2026-11-24", machine="m")[0]["entries"][0]["discovery_note"]
            self.assertLessEqual(len(note), 1000)
            self.assertIn(" Package: npm:@playwright/mcp.", note, n)
            self.assertTrue(note.endswith(" Not reviewed."), n)

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
