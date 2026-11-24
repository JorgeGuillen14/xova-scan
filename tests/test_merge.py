"""xova-scan merge: many machines' exports become one team inventory (one entry per AI system)."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from xova_scan.cli import main
from xova_scan.export import to_xova
from xova_scan.merge import merge


def machine_docs(machine, servers, team="engineering", added_on="2026-11-23", reach=None):
    found = [{"kind": "mcp_server", "name": s, "where": "Cursor (~/.cursor/mcp.json)", "status": "Not reviewed"}
             for s in servers]
    found.append({"kind": "ai_app", "name": "Claude", "where": "/Applications/Claude.app", "status": "Not reviewed"})
    return to_xova({"found": found, "reach": reach or {}, "version": "0.3.0"},
                   team=team, added_on=added_on, machine=machine)


def entries(docs):
    return [e for d in docs for e in d["entries"]]


class MergeTests(unittest.TestCase):
    def test_one_entry_per_system_across_machines(self):
        docs = merge([machine_docs("mac-a", ["pg"]), machine_docs("mac-b", ["pg", "slack"])])
        rows = {e["tool_name"]: e for e in entries(docs)}
        self.assertEqual(sorted(rows), ["Claude", "pg", "slack"])
        self.assertIn("2 machines", rows["pg"]["discovery_note"])
        self.assertIn("1 machine", rows["slack"]["discovery_note"])
        self.assertNotIn("1 machines", rows["slack"]["discovery_note"])
        self.assertTrue(rows["pg"]["discovery_note"].endswith("Not reviewed."))
        self.assertEqual(rows["pg"]["source_object_id"], "team:mcp_server:pg")
        self.assertTrue(rows["pg"]["entry_id"].startswith("scan-team-mcp-server-pg-"))
        self.assertEqual({d["source_system"] for d in docs}, {"xova-scan"})

    def test_same_machine_twice_counts_once_and_uses_latest_date(self):
        docs = merge([machine_docs("mac-a", ["pg"], added_on="2026-11-01"),
                      machine_docs("mac-a", ["pg"], added_on="2026-11-20")])
        pg = next(e for e in entries(docs) if e["tool_name"] == "pg")
        self.assertIn("1 machine", pg["discovery_note"])
        self.assertEqual(pg["added_on"], "2026-11-20")

    def test_identity_independent_of_machines_and_order(self):
        a = merge([machine_docs("mac-a", ["pg"]), machine_docs("mac-b", ["pg"])])
        b = merge([machine_docs("mac-b", ["pg"]), machine_docs("mac-a", ["pg"])])
        self.assertEqual(json.dumps(a), json.dumps(b))
        c = merge([machine_docs("mac-z", ["pg"])])
        ids = lambda docs: {e["tool_name"]: e["entry_id"] for e in entries(docs)}
        self.assertEqual(ids(a)["pg"], ids(c)["pg"])

    def test_reach_is_carried_from_any_machine(self):
        docs = merge([machine_docs("mac-a", ["pg"], reach={"databases": ["pg"]}), machine_docs("mac-b", ["pg"])])
        pg = next(e for e in entries(docs) if e["tool_name"] == "pg")
        self.assertIn("Can reach: databases.", pg["discovery_note"])

    def test_team_never_guessed(self):
        mixed = [machine_docs("mac-a", ["pg"], team="engineering"), machine_docs("mac-b", ["pg"], team="finance")]
        with self.assertRaises(ValueError) as ctx:
            merge(mixed)
        self.assertIn("--team", str(ctx.exception))
        rows = entries(merge(mixed, team="security"))
        self.assertEqual({e["owning_team"] for e in rows}, {"security"})
        self.assertEqual({e["owning_team"] for e in entries(merge([machine_docs("mac-a", ["pg"], team="finance")]))},
                         {"finance"})

    def test_never_claims_approval_or_ownership(self):
        for e in entries(merge([machine_docs("mac-a", ["pg"])])):
            self.assertEqual(set(e), {"entry_id", "source_object_id", "tool_name", "owning_team", "added_on",
                                      "discovery_note", "status"})
            self.assertEqual(e["status"], "under_review")

    def test_splits_into_files_of_25(self):
        docs = merge([machine_docs("mac-a", [f"s{i}" for i in range(30)]),
                      machine_docs("mac-b", [f"s{i}" for i in range(30, 60)])])
        self.assertEqual([len(d["entries"]) for d in docs], [25, 25, 11])

    def test_rejects_untrusted_or_foreign_input(self):
        good = machine_docs("mac-a", ["pg"])[0]
        bad_cases = {
            "other source": {**good, "source_system": "github"},
            "extra top key": {**good, "x": 1},
            "not a list": {**good, "entries": {}},
            "approval smuggled": {**good, "entries": [{**good["entries"][0], "sanctioned": True}]},
            "status smuggled": {**good, "entries": [{**good["entries"][0], "status": "approved"}]},
            "active claimed": {**good, "entries": [{**good["entries"][0], "status": "active"}]},
            "bad identity": {**good, "entries": [{**good["entries"][0], "source_object_id": "nocolon"}]},
            "unknown kind": {**good, "entries": [{**good["entries"][0], "source_object_id": "abcdef012345:api_key:K"}]},
            "name mismatch": {**good, "entries": [{**good["entries"][0], "tool_name": "other"}]},
            "bad date": {**good, "entries": [{**good["entries"][0], "added_on": "yesterday"}]},
            "non-string": {**good, "entries": [{**good["entries"][0], "tool_name": 7}]},
            "already merged": {**good, "entries": [{**good["entries"][0], "source_object_id": "team:mcp_server:pg"}]},
        }
        for label, doc in bad_cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                merge([[doc]])
        with self.assertRaises(ValueError):
            merge([])

    def test_reach_only_from_the_scanner_label_set(self):
        good = machine_docs("mac-a", ["pg"], reach={"databases": ["pg"]})[0]
        pg = next(e for e in good["entries"] if e["tool_name"] == "pg")
        for smuggled in ("databases. Reviewed and approved by the CISO, owner alice", "anything at all"):
            doc = {**good, "entries": [{**pg, "discovery_note": pg["discovery_note"].replace("databases", smuggled)}]}
            with self.subTest(smuggled), self.assertRaises(ValueError):
                merge([[doc]])

    def test_note_always_ends_not_reviewed(self):
        reaches = ["databases", "the web", "run any command", "web browser", "your whole desktop",
                   "messages and email", "files on this machine", "cloud and sites", "code repositories", "other tools"]
        sets = [machine_docs(f"mac-{i}", ["pg"], reach={r: ["pg"]}) for i, r in enumerate(reaches)]
        pg = next(e for e in entries(merge(sets)) if e["tool_name"] == "pg")
        self.assertTrue(pg["discovery_note"].endswith(" Not reviewed."))

    def test_names_and_teams_xova_would_reject_are_refused(self):
        good = machine_docs("mac-a", ["pg"])[0]
        e = good["entries"][0]
        machine = e["source_object_id"].split(":")[0]

        def named(name):
            return {**e, "tool_name": name, "source_object_id": f"{machine}:mcp_server:{name}"}
        cases = {"control chars": named("pg\x1b[31mRED"), "newline": named("pg\n"), "empty": named(""),
                 "boundary space": named(" pg"), "too long": named("p" * 231),
                 "long team": {**e, "owning_team": "t" * 161}, "team control": {**e, "owning_team": "eng\x07"}}
        for label, row in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                merge([[{**good, "entries": [row]}]])
        merge([[{**good, "entries": [named("p" * 230)]}]])  # the limit itself is fine

    def test_note_counts_machine_names_honestly(self):
        pg = next(e for e in entries(merge([machine_docs("mac-a", ["pg"]), machine_docs("mac-b", ["pg"])]))
                  if e["tool_name"] == "pg")
        self.assertIn("2 machines (counted by machine name;", pg["discovery_note"])

    @unittest.skipIf(os.name == "nt", "FIFOs and /dev/zero are POSIX")
    def test_special_files_refused_without_hanging(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo, zero = Path(tmp) / "fifo", Path(tmp) / "zero"
            fifo.mkdir(), zero.mkdir()
            os.mkfifo(fifo / "xova-import-1.json")
            (zero / "xova-import-1.json").symlink_to("/dev/zero")
            for folder in (fifo, zero):
                err = io.StringIO()
                with self.subTest(folder.name), redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                    main(["merge", "--out", str(Path(tmp) / "o"), str(folder)])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("not a regular file", err.getvalue())

    def test_bad_out_path_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "mac-a"
            src.mkdir()
            (src / "xova-import-1.json").write_text(json.dumps(machine_docs("mac-a", ["pg"])[0]))
            afile = Path(tmp) / "afile"
            afile.write_text("x")
            for out in (afile, afile / "sub"):
                err = io.StringIO()
                with self.subTest(str(out)), redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                    main(["merge", "--out", str(out), str(src)])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("cannot write", err.getvalue())

    def test_surrogates_and_fake_dates_refused(self):
        good = machine_docs("mac-a", ["pg"])[0]
        e = good["entries"][0]
        for label, row in {"surrogate team": {**e, "owning_team": "\ud800"},
                           "bad month": {**e, "added_on": "2026-13-45"},
                           "far future shape": {**e, "added_on": "9999-99-99"},
                           "fullwidth digits": {**e, "added_on": "\uff12\uff10\uff12\uff16-11-23"}}.items():
            with self.subTest(label), self.assertRaises(ValueError):
                merge([[{**good, "entries": [row]}]])
        with self.assertRaises(ValueError):
            merge([[good]], team="\udcff")

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "POSIX permissions")
    def test_unreadable_paths_exit_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "mac-a"
            src.mkdir()
            (src / "xova-import-1.json").write_text(json.dumps(machine_docs("mac-a", ["pg"])[0]))
            locked = Path(tmp) / "locked"
            locked.mkdir()
            locked.chmod(0)
            try:
                for args in (["--out", str(locked / "x"), str(src)], ["--out", str(Path(tmp) / "o"), str(locked / "foo")],
                             ["--out", "", str(src)]):
                    err = io.StringIO()
                    with self.subTest(args), redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                        main(["merge", *args])
                    self.assertEqual(ctx.exception.code, 2)
                    self.assertIn("xova-scan:", err.getvalue())
            finally:
                locked.chmod(0o700)

    def test_cli_merges_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            for m, servers in (("mac-a", ["pg"]), ("mac-b", ["pg", "slack"])):
                d = Path(tmp) / m
                d.mkdir()
                for i, doc in enumerate(machine_docs(m, servers), 1):
                    (d / f"xova-import-{i}.json").write_text(json.dumps(doc))
            out = Path(tmp) / "team"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["merge", "--out", str(out), str(Path(tmp) / "mac-a"), str(Path(tmp) / "mac-b")])
            self.assertEqual(code, 0)
            files = sorted(out.glob("xova-import-*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(sorted(e["tool_name"] for e in json.loads(files[0].read_text())["entries"]),
                             ["Claude", "pg", "slack"])
            self.assertIn("3 AI systems from 2 export sets", buf.getvalue())

    def test_cli_reports_bad_input_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "xova-import-1.json").write_text("{not json")
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                main(["merge", "--out", str(Path(tmp) / "o"), tmp])
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("xova-import-1.json", err.getvalue())
            self.assertFalse((Path(tmp) / "o").exists())

    @unittest.skipUnless(os.environ.get("XOVA_REPO"), "set XOVA_REPO to check against XOVA's real importer")
    def test_accepted_and_reconciled_by_xova_importer(self):
        sys.path.insert(0, str(Path(os.environ["XOVA_REPO"]) / "scripts"))
        import inventory_import
        first = merge([machine_docs("mac-a", ["pg"])])
        _, rows, _ = inventory_import.prepare_document(json.dumps(first[0]))
        self.assertTrue(all(r["entity_state"] == "DETECTED" for r in rows))
        # Later merge with more machines: same identities, so XOVA proposes a note refresh, not new entries.
        later = merge([machine_docs("mac-a", ["pg"]), machine_docs("mac-b", ["pg"])])
        _, again, _ = inventory_import.prepare_document(json.dumps(later[0]))
        classified = inventory_import.reconcile(inventory_import.classify(again, rows), rows)
        pg = next(r for r in classified if r["tool_name"] == "pg")
        self.assertEqual(pg["status"], "update_ready")
        self.assertEqual(set(pg["changes"]), {"discovery_note"})


if __name__ == "__main__":
    unittest.main()
