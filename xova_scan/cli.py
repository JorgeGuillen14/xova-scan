import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import scan, validate_rules, __version__

LABELS = {"mcp_server": "MCP servers", "ai_app": "AI apps", "ai_library": "AI libraries in code", "api_key": "AI keys (names only)"}


def _print(report):
    found = report["found"]
    counts = Counter(f["kind"] for f in found)
    print(f"xova-scan {report['version']}: found {len(found)} AI items on this machine\n")
    for kind, label in LABELS.items():
        items = [f for f in found if f["kind"] == kind]
        if not items:
            continue
        print(f"{label} ({counts[kind]})")
        for f in items:
            print(f"  - {f['name']}  [{f['status']}]  {f['where']}")
        print()
    findings = report["findings"]
    print(f"Rule findings ({len(findings)})" if findings else "Rule findings: none")
    for f in findings:
        print(f"  ! {f['rule']}: {f['subject']}  {f['why']}")
    if report["unreadable"]:
        print("\nCould not read (not proof of no AI):")
        for u in report["unreadable"]:
            print(f"  ? {u}")
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
