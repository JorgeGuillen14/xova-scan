import argparse
import json
import sys
from pathlib import Path

from . import scan, validate_rules, __version__

LABELS = {"mcp_server": "MCP servers", "ai_app": "AI apps", "ai_library": "AI libraries in code", "api_key": "AI keys (names only)"}


_CONTROL = {c: f"\\x{c:02x}" for c in [*range(32), 127, *range(128, 160)]}


def _c(value):
    """Terminal view only: control characters from file names are shown escaped, so they can't forge lines."""
    return str(value).translate(_CONTROL)


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _print(report):
    found, findings = report["found"], report["findings"]
    print(f"xova-scan {report['version']}: {_plural(len(found), 'AI item')} on this machine, "
          f"{_plural(len(findings), 'problem')}\n")
    for kind, label in LABELS.items():
        items = [f for f in found if f["kind"] == kind]
        if not items:
            continue
        print(f"{label} ({len(items)})")
        if kind == "ai_library":
            groups = {}
            for f in items:
                groups.setdefault((f["name"], f["status"]), []).append(f["where"])
            for (name, status), wheres in groups.items():
                where = wheres[0] if len(wheres) == 1 else _plural(len(wheres), "project")
                print(f"  - {_c(name)}  [{status}]  {_c(where)}")
        else:
            for f in items:
                print(f"  - {_c(f['name'])}  [{f['status']}]  {_c(f['where'])}")
        print()
    print(f"Rule findings ({len(findings)})" if findings else "Rule findings: none")
    for f in findings:
        print(f"  ! {f['rule']}: {_c(f['subject'])}  {_c(f['why'])}")
        if f.get("where"):
            print(f"      in {_c(f['where'])}")
    if report["unreadable"]:
        print("\nCould not read (not proof of no AI):")
        for u in report["unreadable"]:
            print(f"  ? {_c(u)}")
    print(f"\n{report['note']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="xova-scan", description="Find the AI on this machine and check it against your rules.")
    p.add_argument("roots", nargs="*", help="folders to search for code (default: your home folder)")
    p.add_argument("--rules", help="JSON rules file, e.g. {\"approved\": [\"Claude\", \"openai\"]}")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
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
    report = scan(home=a.home, apps_dir=a.apps, roots=a.roots or None, rules=rules)
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        _print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
