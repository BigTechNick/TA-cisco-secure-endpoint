#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_secure_endpoint.py - modular input "cisco_secure_endpoint": Cisco Secure
Endpoint data from the API v1 into Splunk.

One input per Secure Endpoint organization (account). Splunk starts it every
minute (interval 60); each run collects the data types that are due, in this
order, each on its own schedule ("every N minutes"):

  events, audit logs, compromises, top malware threats  -> every few minutes / hourly
  computers, vulnerabilities                            -> snapshots, daily by default

Sourcetypes: cisco:se (with EndpointDataType, as the Cisco Security Cloud app
writes it) and cisco:se:audit. host = the account name.

Checkpoints: $SPLUNK_HOME/var/lib/splunk/modinputs/cisco_secure_endpoint/<input>.json
(one section per data type). "Run now" on the Inputs page collects every
selected data type at once.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cisco_se_api as api  # noqa: E402
import cisco_se_collect as collect  # noqa: E402
import cisco_se_modinput as mi  # noqa: E402
import cisco_se_store as store  # noqa: E402

DUE_SLACK = 30                     # seconds: a type due within this is run now (Splunk starts the input every minute)
RETRY_AFTER_FAILURE = 900          # a failed data type is tried again after at most 15 minutes


def _arg(name, title, desc, kind="string", required=False):
    return (name, title, desc, kind, required)


ARGS = [
    _arg("account", "Secure Endpoint account",
         "Name of the Secure Endpoint account (API host, client ID, API key) saved on the add-on's Inputs page.",
         required=True),
]
for _t, (_label, _on, _every, _low, _high) in store.TYPES.items():
    ARGS.append(_arg(f"collect_{_t}", f"Collect {_label.lower()}", f"1 = collect {_label.lower()}, 0 = not. "
                     f"Default {_on}.", "boolean"))
    ARGS.append(_arg(f"{_t}_every", f"{_label}: every (minutes)",
                     f"How often to collect {_label.lower()} ({_low}-{_high} minutes). Default {_every}.", "number"))
ARGS += [
    _arg("event_types_mode", "Event types", "all, only (the event types listed) or except (all but those listed). "
         "Default all.", "string"),
    _arg("event_types", "Event type IDs", "Comma-separated event type IDs (from /v1/event_types).", "string"),
    _arg("audit_types_mode", "Audit log types", "all, only or except. Default all.", "string"),
    _arg("audit_types", "Audit log type IDs", "Comma-separated audit log type IDs, e.g. Computer,Policy.", "string"),
    _arg("groups_mode", "Groups", "all, only or except: which groups' events, computers and vulnerabilities. "
         "Default all.", "string"),
    _arg("groups", "Group GUIDs", "Comma-separated group GUIDs.", "string"),
    _arg("start_hours_ago", "First run: hours back", "How far back the first run of events and audit logs starts "
         "(0-720). Default 24.", "number"),
    _arg("overlap_minutes", "Events overlap (minutes)", "Each events run starts this long before the newest event "
         "already collected; events already sent are skipped by id (0-1440). Default 60.", "number"),
    _arg("audit_overlap_minutes", "Audit overlap (minutes)", "Each audit window starts this long before the previous "
         "one ended (0-1440). Default 10.", "number"),
    _arg("audit_delay_minutes", "Audit delay (minutes)", "Audit windows end this long before now (0-120). Default 2.",
         "number"),
    _arg("page_size", "Page size", "Records per API call (1-500). Default 500.", "number"),
    _arg("log_level", "Log level", "DEBUG, INFO, WARNING or ERROR. Default INFO.", "string"),
]


def run(cfg, name, params):
    level = (params.get("log_level") or "INFO").upper()
    log = mi.setup_logging(name, level)
    checkpoint_dir = cfg.get("checkpoint_dir") or store.state_root()
    lock = mi.RunLock(store.lock_path(name, checkpoint_dir))
    if not lock.acquire():
        log.debug("run skipped: the previous run of this input is still going")
        return 0
    state_file = store.state_path(name, checkpoint_dir)
    state = mi.load_json(state_file, {})
    account_name = params.get("account", "")
    if state.get("account") and state["account"] != account_name:
        log.warning("account changed from %s to %s: checkpoints start over", state["account"], account_name)
        state = {}
    state["account"] = account_name
    marker = store.run_now_path(name, checkpoint_dir)
    run_now = os.path.exists(marker)
    if run_now:
        try:
            os.remove(marker)
        except OSError:
            pass
        log.info("run requested on the Inputs page: collecting every selected data type now")
    now = time.time()
    due = []
    for data_type in store.enabled_types(params):
        nxt = (state.get(data_type) or {}).get("next")
        if run_now or not isinstance(nxt, (int, float)) or now >= nxt - DUE_SLACK:
            due.append(data_type)
    if not due:
        log.debug("run skipped: nothing due")
        return 0

    stop = mi.Stopper()
    out = mi.EventStream()
    written, failures = {}, []
    client = None
    t0 = time.time()

    def save():
        try:
            mi.save_json(state_file, state)
        except OSError as exc:
            log.error("could not save the checkpoint %s: %s", state_file, exc)

    try:
        account = store.Accounts(store.Splunkd(cfg["session_key"])).get(account_name)
        client = store.client_for(account, log=log, should_stop=stop)
        ctx = collect.Context(client, out, account_name, log, stop, params, state, save)
        for data_type in due:
            if stop():
                break
            section = state.setdefault(data_type, {})
            every = store.number(params, f"{data_type}_every") * 60
            started, calls = time.time(), client.calls
            try:
                stats = collect.COLLECTORS[data_type](ctx, section)
                if stop():
                    break
                section["next"] = started + every
                section["last_ok"] = time.time()
                written[data_type] = stats.get("written", 0)
                log.info("collected %s: %s", data_type,
                         collect.describe(data_type, stats, client.calls - calls, time.time() - started))
            except mi.OutputClosed:
                raise
            except api.ApiError as exc:
                if str(exc) == "stopped":
                    break
                section["next"] = started + min(every, RETRY_AFTER_FAILURE)
                failures.append(f"{data_type}: {exc}")
                log.error("failed %s: %s", data_type, exc)
            except Exception as exc:                           # one data type's problem does not stop the others
                section["next"] = started + min(every, RETRY_AFTER_FAILURE)
                failures.append(f"{data_type}: {type(exc).__name__}: {exc}")
                log.exception("failed %s: %s: %s", data_type, type(exc).__name__, exc)
            finally:
                save()
        summary = ", ".join(f"{t} {n}" for t, n in written.items()) or "none"
        if stop():
            log.warning("run stopped: stopped by Splunk (input disabled or restarted, or Splunk stopping); written "
                        "%d (%s). The next run continues from the checkpoints", sum(written.values()), summary)
            return 0
        if failures:
            log.error("run failed: %s; written %d (%s), api calls %d, %.1f s", "; ".join(failures),
                      sum(written.values()), summary, client.calls, time.time() - t0)
            return 1
        log.info("run done: written %d (%s), api calls %d, %.1f s", sum(written.values()), summary, client.calls,
                 time.time() - t0)
        return 0
    except mi.OutputClosed:
        save()
        log.warning("run stopped: Splunk stopped reading this input's events (input disabled or restarted, or "
                    "Splunk stopping); written %d. Events still on their way may not have reached Splunk, so the next "
                    "run sends them again", sum(written.values()))
        return 0
    except store.StoreError as exc:
        log.error("run failed: %s", exc)
        return 1
    except api.ApiError as exc:
        log.error("run failed: %s", exc)
        return 1
    except Exception as exc:                                       # keep the details in the log
        log.exception("run failed: %s: %s", type(exc).__name__, exc)
        return 1
    finally:
        out.close()                                                # never raises


if __name__ == "__main__":
    mi.main("Cisco Secure Endpoint",
            "Cisco Secure Endpoint (AMP for Endpoints) events, audit logs, compromises, computers, vulnerabilities "
            "and top malware threats from the Secure Endpoint API v1.", ARGS, run)
