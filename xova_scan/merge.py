"""Merge many machines' --export-xova files into one team inventory: one entry per AI system.

Inputs come from other people's machines, so every document is checked against the exact
shape xova-scan writes and anything else is refused. The team identity of a system does not
depend on which machines found it, so a later merge refreshes the same XOVA entries.
Nothing here approves, assigns owners or claims a review.
"""
import datetime
import hashlib
import re
import unicodedata

from . import CAPABILITIES
from .export import MAX_ENTRIES, SOURCE_SYSTEM, SYSTEM_KINDS, _slug

_FIELDS = {"entry_id", "source_object_id", "tool_name", "owning_team", "added_on", "discovery_note"}
_MACHINE = re.compile(r"[0-9a-f]{12}")
# Only the scanner's own reach labels are carried over; any other text in a note is dropped or refused.
REACH_LABELS = sorted({label for label, _ in CAPABILITIES} | {"other tools"})
_REACH = re.compile(r" Can reach: ([^.]*)\. Not reviewed\.$")
MAX_NAME = 230   # keeps team:<kind>:<name> within XOVA's 256-character source_object_id
MAX_TEAM = 160


def _real_date(value):
    try:
        return value.isascii() and datetime.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _clean(value, field, limit):
    if (not value or value != value.strip() or len(value) > limit
            or any(unicodedata.category(ch) in ("Cc", "Cs") for ch in value)):
        raise ValueError(f"{field} must be 1..{limit} characters with no control characters or edge spaces")


def _plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _rows(docs):
    for doc in docs:
        if type(doc) is not dict or set(doc) != {"source_system", "entries"} or doc["source_system"] != SOURCE_SYSTEM:
            raise ValueError("not an xova-scan export document")
        if type(doc["entries"]) is not list or len(doc["entries"]) > MAX_ENTRIES:
            raise ValueError("entries must be a list of at most 25")
        for e in doc["entries"]:
            if type(e) is not dict or set(e) != _FIELDS or not all(type(v) is str for v in e.values()):
                raise ValueError("entry is not in xova-scan's export shape")
            machine, sep, key = e["source_object_id"].partition(":")
            kind, sep2, name = key.partition(":")
            if not (sep and sep2 and _MACHINE.fullmatch(machine) and kind in SYSTEM_KINDS and name == e["tool_name"]):
                raise ValueError(f"entry {e['entry_id'][:80]!r} has an identity xova-scan did not write")
            if not _real_date(e["added_on"]):
                raise ValueError(f"entry {e['entry_id'][:80]!r} has a bad date")
            _clean(name, "tool_name", MAX_NAME)
            _clean(e["owning_team"], "owning_team", MAX_TEAM)
            yield machine, kind, name, e


def merge(machine_exports, *, team=None):
    """machine_exports: a list of document lists (one per export file set). Returns team documents."""
    systems = {}
    for docs in machine_exports:
        for machine, kind, name, e in _rows(docs):
            s = systems.setdefault((kind, name), {"machines": set(), "teams": set(), "dates": set(), "reach": set()})
            s["machines"].add(machine)
            s["teams"].add(e["owning_team"])
            s["dates"].add(e["added_on"])
            m = _REACH.search(e["discovery_note"])
            if m:
                labels = m.group(1).split(", ")
                if not set(labels) <= set(REACH_LABELS):
                    raise ValueError(f"entry {e['entry_id'][:80]!r} has a reach xova-scan does not write")
                s["reach"].update(labels)
            elif " Can reach: " in e["discovery_note"]:
                raise ValueError(f"entry {e['entry_id'][:80]!r} has a reach xova-scan does not write")
    if not systems:
        raise ValueError("no xova-scan export entries to merge")
    if team is not None:
        _clean(team, "--team", MAX_TEAM)
    if team is None:
        split = sorted(name for (_, name), s in systems.items() if len(s["teams"]) > 1)
        if split:
            raise ValueError("machines name different departments for " + ", ".join(split[:5])
                             + ": pass --team, xova-scan never guesses one")
    entries = []
    for (kind, name), s in sorted(systems.items()):
        latest = max(s["dates"])
        note = (f"Found by xova-scan on {_plural(len(s['machines']), 'machine')} (counted by machine name; "
                f"latest scan {latest}): "
                f"{SYSTEM_KINDS[kind]}.")
        if s["reach"]:
            note += f" Can reach: {', '.join(sorted(s['reach']))}."
        note += " Not reviewed."
        key = f"{kind}:{name}"
        entries.append({
            "entry_id": f"scan-team-{_slug(kind)}-{_slug(name)}-{hashlib.sha256(key.encode()).hexdigest()[:8]}",
            "source_object_id": f"team:{key}",
            "tool_name": name,
            "owning_team": team if team is not None else next(iter(s["teams"])),
            "added_on": latest,
            "discovery_note": note,
        })
    return [{"source_system": SOURCE_SYSTEM, "entries": entries[i:i + MAX_ENTRIES]}
            for i in range(0, len(entries), MAX_ENTRIES)]
