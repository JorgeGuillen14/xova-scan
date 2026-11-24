"""--export-xova: the scan becomes XOVA inventory import documents (Not reviewed, never approved)."""
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from xova_scan.cli import main
from xova_scan.export import to_xova

ENTRY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}")
REQUIRED = {"entry_id", "tool_name", "owning_team", "added_on", "status"}
ALLOWED = REQUIRED | {"source_object_id", "discovery_note"}


def report(n_servers=3):
    found = [{"kind": "mcp_server", "name": f"srv{i}", "where": "Cursor (/h/.cursor/mcp.json)", "status": "Not reviewed",
              "runs": "npx"} for i in range(n_servers)]
    found += [{"kind": "ai_app", "name": "Claude", "where": "/Applications/Claude.app", "status": "Not reviewed"},
              {"kind": "ai_cli", "name": "codex", "where": "/opt/homebrew/bin/codex", "status": "Not reviewed"},
              {"kind": "ai_library", "name": "openai", "where": "/h/code/a/package.json", "status": "Not reviewed"},
              {"kind": "ai_library", "name": "openai", "where": "/h/code/b/package.json", "status": "Not reviewed"},
              {"kind": "api_key", "name": "OPENAI_API_KEY", "where": "/h/code/a/.env", "status": "Not reviewed"},
              {"kind": "cloud_account", "name": "AWS", "where": "/h/.aws", "status": "Not reviewed"}]
    return {"found": found, "reach": {"databases": ["srv0"]}, "version": "0.3.0"}


class ExportTests(unittest.TestCase):
    def docs(self, rep=None, **kw):
        return to_xova(rep or report(), team=kw.get("team", "engineering"), added_on="2026-11-23", machine="mac-1")

    def test_documents_match_xova_import_shape(self):
        docs = self.docs()
        self.assertEqual(len(docs), 1)
        doc = docs[0]
        self.assertEqual(set(doc), {"source_system", "entries"})
        self.assertEqual(doc["source_system"], "xova-scan")
        names = sorted(e["tool_name"] for e in doc["entries"])
        # systems in use only: servers, apps, CLIs, one entry per library; keys and cloud hints are not systems
        self.assertEqual(names, ["Claude", "codex", "openai", "srv0", "srv1", "srv2"])
        for e in doc["entries"]:
            self.assertTrue(REQUIRED <= set(e) <= ALLOWED, e)
            self.assertTrue(ENTRY_ID.fullmatch(e["entry_id"]))
            self.assertEqual(e["owning_team"], "engineering")
            # XOVA requires a lifecycle status; found-but-unreviewed is under_review (never active/approved)
            self.assertEqual(e["status"], "under_review")
        db = next(e for e in doc["entries"] if e["tool_name"] == "srv0")
        self.assertIn("databases", db["discovery_note"])
        lib = next(e for e in doc["entries"] if e["tool_name"] == "openai")
        self.assertIn("2 projects", lib["discovery_note"])

    def test_never_claims_approval_or_ownership(self):
        for e in self.docs()[0]["entries"]:
            for field in ("sanctioned", "business_owner", "sponsor", "steward", "assessment", "entity_state"):
                self.assertNotIn(field, e)

    def test_splits_into_files_of_25(self):
        docs = self.docs(report(60))
        self.assertEqual([len(d["entries"]) for d in docs], [25, 25, 13])

    def test_deterministic_and_stable_ids(self):
        a, b = self.docs(), self.docs()
        self.assertEqual(json.dumps(a), json.dumps(b))
        rep = report()
        rep["found"].reverse()
        self.assertEqual(json.dumps(self.docs(rep)), json.dumps(a))

    def test_team_is_required_and_never_invented(self):
        with self.assertRaises(ValueError):
            to_xova(report(), team="", added_on="2026-11-23", machine="m")

    def test_cli_writes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            (home / ".cursor").mkdir(parents=True)
            (home / ".cursor/mcp.json").write_text(json.dumps({"mcpServers": {"pg": {"command": "uvx", "args": ["mcp-postgres==1"]}}}))
            out = Path(tmp) / "out"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--no-activity", "--export-xova", str(out), "--team", "engineering",
                             "--home", str(home), "--apps", "/none", str(home / "nocode")])
            self.assertEqual(code, 0)
            files = sorted(out.glob("xova-import-*.json"))
            self.assertEqual(len(files), 1)
            self.assertIn("pg", files[0].read_text())
            self.assertIn("xova-import-1.json", buf.getvalue())

    @unittest.skipUnless(os.environ.get("XOVA_REPO"), "set XOVA_REPO to check against XOVA's real importer")
    def test_accepted_by_xova_importer(self):
        sys.path.insert(0, str(Path(os.environ["XOVA_REPO"]) / "scripts"))
        import inventory_import
        for doc in self.docs(report(30)):
            source, rows, scan = inventory_import.prepare_document(json.dumps(doc))
            self.assertEqual(source, "xova-scan")
            self.assertTrue(all(r["entity_state"] == "DETECTED" for r in rows))


if __name__ == "__main__":
    unittest.main()
