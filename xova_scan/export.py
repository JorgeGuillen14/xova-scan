"""Turn a scan into XOVA inventory import documents.

Each AI system in use becomes one entry that XOVA admits as DETECTED and Not reviewed.
Nothing here approves, assigns owners or claims a review. The department is an explicit
input, never invented. Same scan, same inputs: byte-identical documents.
"""
import hashlib
import re

SOURCE_SYSTEM = "xova-scan"
MAX_ENTRIES = 25
SYSTEM_KINDS = {"mcp_server": "MCP server", "ai_app": "AI app", "ai_cli": "AI command-line tool",
                "ai_library": "AI library"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "item"


def to_xova(report: dict, *, team: str, added_on: str, machine: str) -> list:
    if not isinstance(team, str) or not team.strip():
        raise ValueError("--team is required: XOVA needs the owning department, and xova-scan never guesses one")
    machine_id = hashlib.sha256(machine.encode()).hexdigest()[:12]
    reach_of = {name: cap for cap, names in report.get("reach", {}).items() for name in names}
    grouped, packages = {}, {}
    for f in report.get("found", []):
        if f["kind"] in SYSTEM_KINDS:
            grouped.setdefault((f["kind"], f["name"]), []).append(f["where"])
            if f.get("package"):
                packages.setdefault((f["kind"], f["name"]), set()).add(f["package"])
    entries = []
    for (kind, name), wheres in sorted(grouped.items()):
        label = SYSTEM_KINDS[kind]
        where = f"{len(wheres)} projects" if len(wheres) > 1 else wheres[0]
        note = f"Found by xova-scan {report.get('version', '')} on {added_on}: {label} ({where})."
        pkgs = sorted(packages.get((kind, name), ()))
        if len(pkgs) == 1:  # two configs with one label running different packages: no single identity to state
            note += f" Package: {pkgs[0]}."
        if name in reach_of:
            note += f" Can reach: {reach_of[name]}."
        note += " Not reviewed."
        key = f"{kind}:{name}"
        entries.append({
            "entry_id": f"scan-{machine_id}-{_slug(kind)}-{_slug(name)}-{hashlib.sha256(key.encode()).hexdigest()[:8]}",
            "source_object_id": f"{machine_id}:{key}",
            "tool_name": name,
            "owning_team": team.strip(),
            "added_on": added_on,
            "discovery_note": note[:1000],
            "status": "under_review",  # found, not reviewed; XOVA requires a lifecycle status
        })
    return [{"source_system": SOURCE_SYSTEM, "entries": entries[i:i + MAX_ENTRIES]}
            for i in range(0, len(entries), MAX_ENTRIES)] or [{"source_system": SOURCE_SYSTEM, "entries": []}]
