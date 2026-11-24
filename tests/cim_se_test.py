#!/usr/bin/env python3
"""
cim_se_test.py - offline checks of the cisco:se CIM settings added in 1.0.1.

The Cisco Security Cloud app's settings for cisco:se outrank this add-on, so these settings must
not reuse a key Cisco sets, and this add-on's action lookup must sort after Cisco's. Also a Python
stand-in for the signature / severity EVALs and the action lookup on made-up events.
"""
import csv
import os
import re
import sys

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "TA-cisco-secure-endpoint")
# Keys the Cisco Security Cloud app (4.1.3) sets in [cisco:se]
CISCO_KEYS = {
    "EVAL-vendor_product", "EVAL-file_hash", "EVAL-user", "LOOKUP-cisco_se_events_actions_lookup",
    "FIELDALIAS-event_type_as_category", "FIELDALIAS-computer_hostname_as_dest", "FIELDALIAS-file_file_name_as_file_name",
    "FIELDALIAS-file_file_path_as_file_path", "FIELDALIAS-detection_as_signature", "FIELDALIAS-process_cmd_line",
    "FIELDALIAS-process_id", "FIELDALIAS-process_name", "FIELDALIAS-process_path", "FIELDALIAS-process_guid",
    "FIELDALIAS-parent_process", "FIELDALIAS-parent_process_id", "FIELDALIAS-parent_process_name",
    "FIELDALIAS-parent_process_path", "FIELDALIAS-parent_process_guid", "FIELDALIAS-tactics", "FIELDALIAS-mitre_technique",
}
CISCO_EVAL_FIELDS = {"vendor_product", "file_hash", "user"}
FAILS = []


def check(ok, msg):
    print(("PASS  " if ok else "FAIL  ") + msg)
    if not ok:
        FAILS.append(msg)


def conf(name):
    out, stanza = {}, None
    for line in open(os.path.join(APP, "default", name), encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            stanza = s[1:-1]
            out.setdefault(stanza, {})
        elif "=" in s:
            k, v = (x.strip() for x in s.split("=", 1))
            out[stanza][k] = v
    return out


def signature(e):                     # EVAL-signature
    if e.get("detection"):
        return e["detection"]
    tm = e.get("file.attack_details.threat_module")
    if tm:
        sm = e.get("file.attack_details.threat_submodule")
        return tm + (" / " + sm if sm else "")   # empty submodule: no " / "
    ind = e.get("file.attack_details.indicators{}.short_description")
    if ind:
        return ind[0]
    if e.get("error.description"):
        return e["event_type"] + ": " + e["error.description"]
    return e.get("event_type")


def severity(e):                      # EVAL-severity
    if e.get("severity"):
        return e["severity"].lower()
    return "medium" if e.get("event_type_id") == "1090519103" else None


EVENTS = [
    (dict(event_type="Threat Detected", event_type_id="1090519054", detection="W32.Example.Trojan", severity="Medium"),
     "W32.Example.Trojan", "medium", "allowed"),
    (dict(event_type="Exploit Prevention", event_type_id="1090519103", **{
        "file.attack_details.threat_module": "Hacking Tool", "file.attack_details.threat_submodule": "PsExec",
        "file.attack_details.indicators{}.short_description": ["PsExec Execution"]}),
     "Hacking Tool / PsExec", "medium", "allowed"),
    (dict(event_type="Exploit Prevention", event_type_id="1090519103", **{
        "file.attack_details.indicators{}.short_description": ["Example Indicator"]}),
     "Example Indicator", "medium", "allowed"),
    (dict(event_type="Exploit Prevention", event_type_id="1090519103", **{
        "file.attack_details.threat_module": "Script Execution", "file.attack_details.threat_submodule": ""}),
     "Script Execution", "medium", "allowed"),
    (dict(event_type="Quarantine Failure", event_type_id="2164260880", severity="Medium", **{"error.description": "Cannot delete"}),
     "Quarantine Failure: Cannot delete", "medium", "allowed"),
    (dict(event_type="Threat Quarantined", event_type_id="553648143", detection="W32.Example.Trojan", severity="High"),
     "W32.Example.Trojan", "high", "blocked"),
]


def main():
    props = conf("props.conf")["cisco:se"]
    mine = {k: v for k, v in props.items() if k.startswith(("EVAL-", "LOOKUP-", "FIELDALIAS-"))}
    check(bool(mine), "props.conf [cisco:se] has CIM settings")
    for key in mine:
        reused = key in CISCO_KEYS or (key.startswith("EVAL-") and key[5:] in CISCO_EVAL_FIELDS)
        check(not reused, f"[cisco:se] {key} is not a key Cisco Security Cloud sets")
    lookups = [k for k in mine if k.startswith("LOOKUP-")]
    check(all(k > "LOOKUP-cisco_se_events_actions_lookup" for k in lookups),
          f"lookup class names sort after Cisco's {lookups}")
    lk = props.get("LOOKUP-se_cim_action", "")
    m = re.match(r"(\S+)\s+(\S+)\s+OUTPUT\s+(\S+)$", lk)
    check(m is not None and m.group(2) != m.group(3), "action lookup: event_type_id in, action out (no cycle)")

    transforms = conf("transforms.conf")
    table_name = m.group(1) if m else ""
    fname = transforms.get(table_name, {}).get("filename", "missing.csv")
    rows = {r["event_type_id"]: r["action"] for r in csv.DictReader(open(os.path.join(APP, "lookups", fname), encoding="utf-8"))}
    check({"553648143", "553648147"} <= set(rows) and rows["553648143"] == rows["553648147"] == "blocked",
          "lookup keeps Cisco's two quarantine rows (blocked)")
    check(set(rows.values()) <= {"allowed", "blocked", "deferred"}, "lookup outputs CIM Malware actions only")

    meta = open(os.path.join(APP, "metadata", "default.meta"), encoding="utf-8").read()
    check(re.search(r"^\[lookups\]\s*\nexport = system", meta, re.M) is not None,
          "metadata exports lookups (the table must be visible from other apps)")

    for e, sig, sev, act in EVENTS:
        got = (signature(e), severity(e), rows.get(e["event_type_id"]))
        check(got == (sig, sev, act), f"{e['event_type']}: {got}")
    print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
