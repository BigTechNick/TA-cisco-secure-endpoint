# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_se_collect.py - one collector per data type. Each takes a Context (API
client, event stream, settings) and the data type's own checkpoint (a dict it
updates), writes events, and returns its counts.

Records are written as the API returns them, with "EndpointDataType" added
(and, for events, "groups": the names of the event's groups), the way the
Cisco Security Cloud app writes sourcetype cisco:se, so its CIM mappings and
dashboards apply. Audit logs go to sourcetype cisco:se:audit unchanged.

  events           /v1/events from a checkpoint (start_date = newest event seen - overlap),
                   newest first, page by page; duplicates skipped by event id
  audit            /v1/audit_logs in windows of at most an hour (start_time, end_time),
                   duplicates skipped by a hash of the record (audit_log_id is not unique)
  compromises      /v1/compromises; only new or changed ones (status, updated_at)
  metrics          /v1/metrics/top_malware_threats; one event per run
  computers        /v1/computers; one event per computer per run (a snapshot)
  vulnerabilities  /v1/vulnerabilities; one event per entry per run (a snapshot)
"""
import hashlib
import json
import time

import cisco_se_api as api
import cisco_se_modinput as mi
import cisco_se_store as store

SOURCETYPE = "cisco:se"
AUDIT_SOURCETYPE = "cisco:se:audit"
GROUPS_TTL = 3600                 # group names are fetched again after an hour, or for an unknown group
AUDIT_WINDOW = 3600               # audit windows of at most an hour (the checkpoint is saved after each)
SEEN_MARGIN = 600                 # ids are kept this long beyond the overlap


class Context:
    def __init__(self, client, out, host, log, stop, params, state, save):
        self.client, self.out, self.host, self.log, self.stop = client, out, host, log, stop
        self.params, self.state, self.save = params, state, save
        self.now = time.time()
        self._groups_fresh = False

    def number(self, key):
        return store.number(self.params, key)

    def selection(self, list_key):
        """(mode, set of IDs) for event_types, audit_types or groups."""
        return store.mode(self.params, list_key), set(store.comma_list(self.params.get(list_key)))

    # ---- group names (for events)
    def groups(self, need=()):
        doc = self.state.setdefault("groups", {})
        names = doc.get("names") if isinstance(doc.get("names"), dict) else {}
        stale = not names or self.now - (doc.get("at") or 0) > GROUPS_TTL
        missing = [g for g in need if g not in names]
        if (stale or missing) and not self._groups_fresh:
            self._groups_fresh = True
            fresh = {}
            try:
                for records, _page in self.client.pages("/v1/groups", {"limit": 100}):
                    for g in records:
                        if g.get("guid"):
                            fresh[g["guid"]] = g.get("name")
            except api.ApiError as exc:
                if str(exc) == "stopped":
                    raise
                # events still go out; their "groups" lists only the names already known
                self.log.warning("group names could not be fetched (%s); using the %d known", exc, len(names))
                return names
            names = fresh
            self.state["groups"] = {"at": self.now, "names": names}
            self.log.debug("group names fetched: %d groups", len(names))
        return names


def event_time(rec, fallback):
    ts = rec.get("timestamp")
    if isinstance(ts, (int, float)) and ts > 0:
        nanos = rec.get("timestamp_nanoseconds")
        return float(ts) + (nanos / 1e9 if isinstance(nanos, (int, float)) and 0 <= nanos < 1e9 else 0.0)
    return api.parse_time(rec.get("date")) or fallback


def record_key(rec):
    return hashlib.sha1(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:24]


def with_type(rec, data_type):
    out = dict(rec)
    out["EndpointDataType"] = data_type
    return out


def group_ids_of(rec):
    ids = set(g for g in (rec.get("group_guids") or []) if isinstance(g, str))
    if isinstance(rec.get("group_guid"), str):
        ids.add(rec["group_guid"])
    for g in rec.get("groups") or []:
        if isinstance(g, dict) and isinstance(g.get("guid"), str):
            ids.add(g["guid"])
    return ids


def group_excluded(rec, group_mode, group_ids):
    if group_mode == "all" or not group_ids:
        return False
    ids = group_ids_of(rec)
    if group_mode == "only":
        return bool(ids) and not (ids & group_ids)
    return bool(ids & group_ids)


# ------------------------------------------------------------------ events

def collect_events(ctx, st):
    overlap = ctx.number("overlap_minutes") * 60
    page_size = ctx.number("page_size")
    type_mode, type_ids = ctx.selection("event_types")
    group_mode, group_ids = ctx.selection("groups")
    stats = {"written": 0, "duplicates": 0, "excluded": 0, "pages": 0}
    seen = {k: v for k, v in (st.get("seen") or {}).items() if isinstance(v, (int, float))}
    committed = dict(seen)
    end = st.get("end") if isinstance(st.get("end"), (int, float)) else None
    if end is None:
        start = st.get("start") if isinstance(st.get("start"), (int, float)) else \
            ctx.now - ctx.number("start_hours_ago") * 3600
        st["start"] = start
        ctx.log.info("events: first run, collecting from %s", api.iso(start))
    else:
        start = end - overlap
    params = {"limit": page_size, "start_date": api.iso(start)}
    if type_mode == "only":
        params["event_type[]"] = sorted(type_ids, key=int)
    if group_mode == "only":
        params["group_guid[]"] = sorted(group_ids)
    newest = end
    ok = False
    try:
        for records, page in ctx.client.pages("/v1/events", params):
            stats["pages"] = page
            oldest_on_page = None
            need = set()
            for rec in records:
                need.update(g for g in rec.get("group_guids") or [] if isinstance(g, str))
            names = ctx.groups(need) if need else {}
            for rec in records:
                if ctx.stop():
                    break
                ts = event_time(rec, ctx.now)
                oldest_on_page = ts if oldest_on_page is None else min(oldest_on_page, ts)
                capped = min(ts, ctx.now)            # an endpoint with its clock ahead must not move the checkpoint
                newest = capped if newest is None else max(newest, capped)
                rid = str(rec.get("id") or "")
                if rid and rid in seen:
                    stats["duplicates"] += 1
                    continue
                type_id = str(rec.get("event_type_id") or "")
                skip = (type_mode == "only" and type_id not in type_ids) or \
                    (type_mode == "except" and type_id in type_ids) or group_excluded(rec, group_mode, group_ids)
                if skip:
                    stats["excluded"] += 1
                    if rid:
                        seen[rid] = ts
                    continue
                out = with_type(rec, "events")
                out["groups"] = [{"guid": g, "name": names[g]} for g in rec.get("group_guids") or [] if g in names]
                ctx.out.write(out, ts, SOURCETYPE, ctx.host)
                if rid:                                # marked as sent only once written
                    seen[rid] = ts
                stats["written"] += 1
            ctx.out.flush()
            if ctx.stop():
                return stats
            # newest first: once a whole page is older than the start, the rest is older still
            if oldest_on_page is not None and oldest_on_page < start - 1:
                break
        ok = True
    finally:
        # Not complete (error, stop): the checkpoint end stays; the ids written are kept so the next
        # run skips them - unless splunkd closed the pipe, when events on their way may be lost and
        # only the ids from before this run are kept (the next run sends them again).
        if ok:
            if newest is not None:
                st["end"] = newest
                st.pop("start", None)
            keep_from = (st.get("end") or start) - overlap - SEEN_MARGIN
            st["seen"] = {k: v for k, v in seen.items() if v >= keep_from}
        else:
            st["seen"] = committed if ctx.out.closed else seen
    stats["newest_min"] = (ctx.now - newest) / 60.0 if newest else None
    return stats


# ------------------------------------------------------------------ audit logs

def collect_audit(ctx, st):
    overlap = ctx.number("audit_overlap_minutes") * 60
    delay = ctx.number("audit_delay_minutes") * 60
    page_size = ctx.number("page_size")
    type_mode, type_ids = ctx.selection("audit_types")
    stats = {"written": 0, "duplicates": 0, "excluded": 0, "pages": 0}
    target = int(ctx.now - delay)
    end = st.get("end") if isinstance(st.get("end"), (int, float)) else None
    seen = {k: v for k, v in (st.get("seen") or {}).items() if isinstance(v, (int, float))}
    committed = dict(seen)
    if end is None:
        start = int(st.get("start")) if isinstance(st.get("start"), (int, float)) else \
            int(target - ctx.number("start_hours_ago") * 3600)
        st["start"] = start
        ctx.log.info("audit: first run, collecting from %s", api.iso(start))
    else:
        start = int(end) - overlap
    stats["window"] = f"{api.iso(start)} to {api.iso(target)}"
    queries = [None] if type_mode != "only" else sorted(type_ids)
    chunk_start = start
    complete = False
    try:
        while chunk_start < target:
            chunk_end = min(chunk_start + AUDIT_WINDOW, target)
            for audit_type in queries:
                params = {"limit": page_size, "start_time": api.iso(chunk_start), "end_time": api.iso(chunk_end)}
                if audit_type:
                    params["audit_log_type"] = audit_type
                for records, page in ctx.client.pages("/v1/audit_logs", params):
                    stats["pages"] += 1
                    oldest_on_page = None
                    for rec in records:
                        if ctx.stop():
                            break
                        ts = api.parse_time(rec.get("created_at")) or chunk_end
                        oldest_on_page = ts if oldest_on_page is None else min(oldest_on_page, ts)
                        key = record_key(rec)
                        if key in seen:
                            stats["duplicates"] += 1
                            continue
                        kind = str(rec.get("audit_log_type") or "")
                        if (type_mode == "only" and kind not in type_ids) or \
                                (type_mode == "except" and kind in type_ids):
                            stats["excluded"] += 1
                            seen[key] = ts
                            continue
                        ctx.out.write(rec, ts, AUDIT_SOURCETYPE, ctx.host)
                        seen[key] = ts
                        stats["written"] += 1
                    ctx.out.flush()
                    if ctx.stop():
                        return stats
                    if oldest_on_page is not None and oldest_on_page < chunk_start - 1:
                        break                       # newest first: the rest is outside the window
            keep_from = chunk_end - overlap - SEEN_MARGIN
            seen = {k: v for k, v in seen.items() if v >= keep_from}
            st["end"] = chunk_end
            st.pop("start", None)
            st["seen"] = seen
            committed = dict(seen)
            ctx.save()
            if chunk_end >= target:
                break
            chunk_start = chunk_end - 1             # 1 s overlap: boundary records are recognised by hash
        complete = True
    finally:
        if not complete:
            st["seen"] = committed if ctx.out.closed else seen
    stats["behind_min"] = (ctx.now - (st.get("end") or start)) / 60.0
    return stats


# ------------------------------------------------------------------ compromises

def collect_compromises(ctx, st):
    known = dict(st.get("known")) if isinstance(st.get("known"), dict) else {}
    before = dict(known)
    current = {}
    stats = {"written": 0, "unchanged": 0, "pages": 0}
    complete = False
    try:
        for records, page in ctx.client.pages("/v1/compromises", {"limit": ctx.number("page_size")}):
            stats["pages"] = page
            for rec in records:
                if ctx.stop():
                    return stats
                computer = rec.get("computer") if isinstance(rec.get("computer"), dict) else {}
                key = f"{computer.get('connector_guid', '')}|{rec.get('created_at', '')}"
                sig = f"{rec.get('updated_at', '')}|{rec.get('status', '')}"
                current[key] = sig
                if known.get(key) == sig:
                    stats["unchanged"] += 1
                    continue
                ts = api.parse_time(rec.get("updated_at")) or api.parse_time(rec.get("created_at")) or ctx.now
                ctx.out.write(with_type(rec, "compromises"), ts, SOURCETYPE, ctx.host)
                known[key] = sig
                stats["written"] += 1
            ctx.out.flush()
        complete = True
    finally:
        # a complete pass replaces the list (resolved compromises drop out); otherwise keep what was sent
        st["known"] = current if complete else (before if ctx.out.closed else known)
    return stats


# ------------------------------------------------------------------ metrics

def collect_metrics(ctx, st):
    doc = ctx.client.get("/v1/metrics/top_malware_threats")
    data = doc.get("data") if isinstance(doc, dict) else None
    stats = {"written": 0}
    if isinstance(data, dict):
        ctx.out.write(with_type(data, "metrics_top_malware_threats"), ctx.now, SOURCETYPE, ctx.host)
        ctx.out.flush()
        stats["written"] = 1
    return stats


# ------------------------------------------------------------------ snapshots

def _snapshot(ctx, path, data_type, group_filter=True):
    params = {"limit": ctx.number("page_size")}
    group_mode, group_ids = ctx.selection("groups") if group_filter else ("all", set())
    if group_mode == "only":
        params["group_guid[]"] = sorted(group_ids)
    stats = {"written": 0, "excluded": 0, "pages": 0, "bytes0": ctx.out.bytes}
    for records, page in ctx.client.pages(path, params):
        stats["pages"] = page
        for rec in records:
            if ctx.stop():
                return stats
            if group_excluded(rec, group_mode, group_ids):
                stats["excluded"] += 1
                continue
            ctx.out.write(with_type(rec, data_type), ctx.now, SOURCETYPE, ctx.host)
            stats["written"] += 1
        ctx.out.flush()
    stats["megabytes"] = (ctx.out.bytes - stats.pop("bytes0")) / 1048576.0
    return stats


def collect_computers(ctx, st):
    return _snapshot(ctx, "/v1/computers", "computers")


def collect_vulnerabilities(ctx, st):
    return _snapshot(ctx, "/v1/vulnerabilities", "vulnerabilities")


COLLECTORS = {
    "events": collect_events,
    "audit": collect_audit,
    "compromises": collect_compromises,
    "metrics": collect_metrics,
    "computers": collect_computers,
    "vulnerabilities": collect_vulnerabilities,
}


def describe(data_type, stats, calls, seconds):
    """The log line's detail for one data type (parsed by the Status dashboard and the Inputs page)."""
    parts = [f"written {stats.get('written', 0)}"]
    for key in ("duplicates", "excluded", "unchanged", "pages"):
        if key in stats:
            parts.append(f"{key} {stats[key]}")
    parts.append(f"api calls {calls}")
    if stats.get("window"):
        parts.append(f"window {stats['window']}")
    if stats.get("behind_min") is not None:
        parts.append("behind %.1f min" % stats["behind_min"])
    if stats.get("newest_min") is not None:
        parts.append("newest %.1f min ago" % stats["newest_min"])
    if stats.get("megabytes") is not None:
        parts.append("%.1f MB" % stats["megabytes"])
    parts.append("%.1f s" % seconds)
    return ", ".join(parts)


__all__ = ["Context", "COLLECTORS", "describe", "mi"]
