import argparse
import json
import os
import stat
import sys
from pathlib import Path

from . import scan, validate_rules, __version__

LABELS = {"mcp_server": "MCP servers", "ai_app": "AI apps", "ai_cli": "AI command-line tools", "ai_library": "AI libraries in code",
          "api_key": "AI keys (names only)", "cloud_account": "Cloud accounts set up here (XOVA can check what AI runs in them)"}


_CONTROL = {c: f"\\x{c:02x}" for c in [*range(32), 127, *range(128, 160)]}


_HOME = None


def _c(value, home=True):
    """Terminal view only: paths under the home folder show as ~/..., and control characters from file
    names are shown escaped, so they can't forge lines."""
    text = str(value)
    if home and _HOME:
        text = text.replace(_HOME + os.sep, "~" + os.sep)
    return text.encode("utf-8", "replace").decode("utf-8").translate(_CONTROL)


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


SEVERITY = ["agent-runs-without-asking", "secret-in-ai-logs", "no-secrets-in-mcp-config", "plaintext-ai-key-in-repo",
            "unpinned-mcp-server", "approved-tools-only"]


def _print(report):
    found, findings, act = report["found"], report["findings"], report.get("activity")
    show_status = any(f["status"] != "Not reviewed" for f in found)  # only meaningful with an approved list

    def tag(status):
        return f"  [{status}]" if show_status else ""
    print(f"xova-scan {report['version']}: {_plural(len(found), 'AI item')} on this machine, "
          f"{_plural(len(findings), 'problem')}\n")

    if report.get("reach"):
        print("What your AI can reach")
        for cap, names in report["reach"].items():
            print(f"  - {cap}: {_c(', '.join(names))}")
        print()

    if act:
        print(f"What your AI did in the last {act['days']} days ({_plural(act['sessions'], 'agent session')})")
        progs = ", ".join(f"{_c(k)} {v}" for k, v in act["top_programs"].items())
        print(f"  - ran {act['shell_commands']} shell commands" + (f" (most: {progs})" if progs else ""))
        if act["risky_commands"]:
            print("  - risky commands: " + ", ".join(f"{k} x{v}" for k, v in act["risky_commands"].items()))
        folders = ", ".join(_c(k) for k in list(act["top_folders"])[:5])
        print(f"  - changed {act['files_changed']} files" + (f" (mostly in {folders})" if folders else ""))
        if act["web_domains"] or act["web_searches"]:
            hosts = act["web_domains"]
            shown = ", ".join(_c(h) for h in hosts[:8]) + (f" and {len(hosts) - 8} more" if len(hosts) > 8 else "")
            print(f"  - reached {_plural(len(hosts), 'web host')}" + (f": {shown}" if hosts else "") +
                  (f"; ran {act['web_searches']} web searches" if act["web_searches"] else ""))
        if act["mcp_tool_calls"]:
            print("  - used tools through MCP: " + ", ".join(f"{_c(k)} {v}" for k, v in act["mcp_tool_calls"].items()))
        if act["subagents_started"]:
            print(f"  - started {act['subagents_started']} sub-agents")
        if act["secrets_in_logs"]:
            n = act["secrets_in_logs"]
            print(f"  - {n} unique {'key or token sits' if n == 1 else 'keys or tokens sit'} in its chat logs")
        print()

    if findings:
        ranked = sorted(findings, key=lambda f: SEVERITY.index(f["rule"]) if f["rule"] in SEVERITY else 99)
        print("Fix first")
        for i, f in enumerate(ranked[:3], 1):
            print(f"  {i}. {_c(f['subject'])}: {_c(f['why'], home=False)}")
        print()

    for kind, label in LABELS.items():
        items = [f for f in found if f["kind"] == kind]
        if not items:
            continue
        print(f"{label} ({len(items)})")
        if kind == "api_key":
            by_where = {}
            for f in items:
                by_where.setdefault(f["where"], []).append(f["name"])
            for where, names in by_where.items():
                print(f"  - {_c(', '.join(sorted(set(names))))}  in {_c(where)}")
        elif kind == "ai_library":
            groups = {}
            for f in items:
                groups.setdefault((f["name"], f["status"]), []).append(f["where"])
            for (name, status), wheres in groups.items():
                where = wheres[0] if len(wheres) == 1 else _plural(len(wheres), "project")
                print(f"  - {_c(name)}{tag(status)}  {_c(where)}")
        else:
            for f in items:
                print(f"  - {_c(f['name'])}{tag(f['status'])}  {_c(f['where'])}")
        print()
    print(f"All rule findings ({len(findings)})" if findings else "Rule findings: none")
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)
    for rule, group in by_rule.items():
        if len(group) == 1:
            f = group[0]
            print(f"  ! {rule}: {_c(f['subject'])}  {_c(f['why'], home=False)}")
            if f.get("where"):
                print(f"      in {_c(f['where'])}")
            continue
        subjects = ", ".join(_c(x) for x in dict.fromkeys(f["subject"] for f in group))
        why = group[0]["why"]
        if rule == "plaintext-ai-key-in-repo":
            why = "AI keys are stored in plain text inside git repositories. For each file, git check-ignore -v <file> must print a rule and git ls-files must not list it."
        print(f"  ! {rule} ({len(group)}): {subjects}")
        print(f"      {_c(why, home=False)}")
        for f in group:
            if f.get("where"):
                print(f"      - {_c(f['subject'])}: {_c(f['where'])}")
    if report["unreadable"]:
        print("\nCould not read (not proof of no AI):")
        for u in report["unreadable"][:20]:
            print(f"  ? {_c(u)}")
    print(f"\n{report['note']}")


MAX_MERGE_FILES = 2000
MAX_MERGE_BYTES = 1024 * 1024
MAX_MERGE_TOTAL = 64 * 1024 * 1024


def _merge_main(argv):
    from .merge import merge
    p = argparse.ArgumentParser(prog="xova-scan merge",
                                description="Combine many machines' --export-xova folders into one team import.")
    p.add_argument("inputs", nargs="+", help="export folders (xova-import-*.json inside) or files, one set per machine")
    p.add_argument("--out", required=True, help="new folder for the team import files")
    p.add_argument("--team", help="XOVA department ID for every entry (required when machines name different ones)")
    a = p.parse_args(argv)
    if not a.out.strip():
        print("xova-scan: --out must name a folder", file=sys.stderr)
        return sys.exit(2)
    out = Path(a.out)
    try:
        taken = out.exists() and any(out.glob("xova-import-*.json"))
    except OSError as exc:
        print(f"xova-scan: cannot use {_c(str(out))}: {_c(exc.strerror or str(exc), home=False)}", file=sys.stderr)
        return sys.exit(2)
    if taken:
        print(f"xova-scan: {_c(str(out))} already has import files; pick a new --out folder", file=sys.stderr)
        return sys.exit(2)
    sets, count, total_bytes = [], 0, 0
    for item in a.inputs:
        path = Path(item)
        try:
            files = sorted(path.glob("xova-import-*.json")) if path.is_dir() else [path]
        except OSError as exc:
            print(f"xova-scan: cannot read {_c(item)}: {_c(exc.strerror or str(exc), home=False)}", file=sys.stderr)
            return sys.exit(2)
        if not files:
            print(f"xova-scan: no xova-import-*.json files in {_c(item)}", file=sys.stderr)
            return sys.exit(2)
        docs = []
        for f in files:
            count += 1
            try:
                if count > MAX_MERGE_FILES:
                    raise ValueError(f"more than {MAX_MERGE_FILES} files")
                if not stat.S_ISREG(f.lstat().st_mode):
                    raise ValueError("not a regular file")
                with f.open("rb") as fh:
                    data = fh.read(MAX_MERGE_BYTES + 1)
                if len(data) > MAX_MERGE_BYTES:
                    raise ValueError("file is over 1 MiB")
                total_bytes += len(data)
                if total_bytes > MAX_MERGE_TOTAL:
                    raise ValueError("inputs total over 64 MiB")
                docs.append(json.loads(data.decode("utf-8")))
            except (OSError, ValueError, UnicodeError, RecursionError) as exc:
                print(f"xova-scan: cannot read {_c(str(f))}: {_c(str(exc)[:200], home=False)}", file=sys.stderr)
                return sys.exit(2)
        sets.append((path, docs))
    try:
        result = merge([docs for _, docs in sets], team=a.team)
    except ValueError as exc:
        print(f"xova-scan: {_c(str(exc), home=False)}", file=sys.stderr)
        return sys.exit(2)
    total = 0
    try:
        out.mkdir(parents=True, exist_ok=True)
        for i, doc in enumerate(result, 1):
            path = out / f"xova-import-{i}.json"
            path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            total += len(doc["entries"])
            print(f"wrote {_c(str(path))} ({len(doc['entries'])} entries)")
    except OSError as exc:
        print(f"xova-scan: cannot write to {_c(str(out))}: {_c(exc.strerror or str(exc), home=False)}", file=sys.stderr)
        return sys.exit(2)
    print(f"{total} AI systems from {len(sets)} export sets: import them in XOVA under Inventory, Import. "
          "Re-run merge with new exports later; XOVA refreshes the same entries.")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["merge"]:
        return _merge_main(argv[1:])
    p = argparse.ArgumentParser(prog="xova-scan", description="Find the AI on this machine and check it against your rules.")
    p.add_argument("roots", nargs="*", help="folders to search for code (default: your home folder)")
    p.add_argument("--rules", help="JSON rules file, e.g. {\"approved\": [\"Claude\", \"openai\"]}")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--no-activity", action="store_true", help="skip reading AI agents' local logs")
    p.add_argument("--export-xova", metavar="DIR", help="write XOVA inventory import files (Not reviewed) to DIR")
    p.add_argument("--team", help="XOVA department ID that will own the imported entries (required with --export-xova)")
    p.add_argument("--days", type=int, default=30, help="how many days of agent activity to read (default 30)")
    p.add_argument("--home", default=str(Path.home()), help=argparse.SUPPRESS)
    p.add_argument("--apps", default="/Applications", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)
    rules = None
    if a.rules:
        try:
            rules = validate_rules(json.loads(Path(a.rules).read_text()))
        except (OSError, ValueError) as exc:
            print(f"xova-scan: bad rules file {a.rules}: {exc}", file=sys.stderr)
            return sys.exit(2)
    report = scan(home=a.home, apps_dir=a.apps, roots=a.roots or None, rules=rules,
                  with_activity=not a.no_activity, days=a.days)
    if a.export_xova:
        import datetime
        import platform as _platform
        from .export import to_xova
        try:
            docs = to_xova(report, team=a.team or "", added_on=datetime.date.today().isoformat(),
                           machine=_platform.node() or "this-machine")
        except ValueError as exc:
            print(f"xova-scan: {exc}", file=sys.stderr)
            return sys.exit(2)
        out = Path(a.export_xova)
        out.mkdir(parents=True, exist_ok=True)
        for i, doc in enumerate(docs, 1):
            path = out / f"xova-import-{i}.json"
            path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            print(f"wrote {path} ({len(doc['entries'])} entries): import it in XOVA under Inventory, Import")
        return 0
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        global _HOME
        _HOME = str(Path(a.home))
        _print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
