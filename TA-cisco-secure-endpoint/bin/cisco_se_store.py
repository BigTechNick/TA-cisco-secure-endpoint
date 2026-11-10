# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_se_store.py - shared helpers for TA-cisco-secure-endpoint.

  * Splunkd: small REST client for splunkd (Splunk's own splunk.rest when
    running inside Splunk; tests pass their own transport).
  * Accounts: Secure Endpoint API host, client ID, API key and optional proxy,
    stored encrypted in Splunk's credential store (storage/passwords).
  * Input settings: data types, schedules, filters; checks; saved settings
    read from the .conf files.
  * Logs and state: per-input log files and checkpoint files, and the latest
    run status per data type read back from an input's log.

Standard library only; runs on Splunk's bundled Python 3.9 and 3.13.
"""
import json
import os
import re
import time
import urllib.parse

import cisco_se_api as api

APP = "TA-cisco-secure-endpoint"
SCHEME = "cisco_secure_endpoint"
REALM = "cisco_se_account"
CHUNK = 255                         # credential store values are stored in parts of this size
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,79}$")
EVENT_TYPE_RE = re.compile(r"^\d{1,12}$")
AUDIT_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_:]{0,63}$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
MODES = ("all", "only", "except")

# Data types, in the order a run collects them. label, default on/off, default and allowed "every" (minutes).
TYPES = {
    "events": ("Events", 1, 5, 1, 1440),
    "audit": ("Audit logs", 1, 5, 1, 1440),
    "compromises": ("Compromises", 0, 60, 5, 10080),
    "metrics": ("Top malware threats", 0, 60, 5, 10080),
    "computers": ("Computers (inventory)", 0, 1440, 60, 10080),
    "vulnerabilities": ("Vulnerabilities", 0, 1440, 60, 10080),
}

# Settings: name -> (default, low, high) for numbers.
NUMBERS = {
    "start_hours_ago": (24, 0, 720),
    "overlap_minutes": (60, 0, 1440),
    "audit_overlap_minutes": (10, 0, 1440),
    "audit_delay_minutes": (2, 0, 120),
    "page_size": (500, 1, 500),
}
for _t, (_label, _on, _every, _low, _high) in TYPES.items():
    NUMBERS[f"{_t}_every"] = (_every, _low, _high)
FLAGS = {f"collect_{t}": spec[1] for t, spec in TYPES.items()}
LISTS = {"event_types": EVENT_TYPE_RE, "audit_types": AUDIT_TYPE_RE, "groups": GUID_RE}
LIST_MODE = {"event_types": "event_types_mode", "audit_types": "audit_types_mode", "groups": "groups_mode"}
TEXTS = {"account": "", "log_level": "INFO", "event_types_mode": "all", "audit_types_mode": "all",
         "groups_mode": "all", "event_types": "", "audit_types": "", "groups": ""}
SETTINGS = tuple(TEXTS) + tuple(FLAGS) + tuple(NUMBERS)


class StoreError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def splunk_home():
    return os.environ.get("SPLUNK_HOME") or os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".."))


def state_root():
    """Where splunkd keeps a modular input's checkpoints: $SPLUNK_DB/modinputs/<scheme>."""
    db = os.environ.get("SPLUNK_DB") or os.path.join(splunk_home(), "var", "lib", "splunk")
    return os.path.join(db, "modinputs", SCHEME)


def safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def log_path(name):
    return os.path.join(splunk_home(), "var", "log", "splunk", f"cisco_se_{safe(name)}.log")


def state_path(name, checkpoint_dir=None):
    return os.path.join(checkpoint_dir or state_root(), f"{safe(name)}.json")


def run_now_path(name, checkpoint_dir=None):
    return os.path.join(checkpoint_dir or state_root(), f"{safe(name)}.run_now")


def lock_path(name, checkpoint_dir=None):
    return os.path.join(checkpoint_dir or state_root(), f"{safe(name)}.lock")


def run_in_progress(name, checkpoint_dir=None):
    """True while a run of the input holds its lock (POSIX; elsewhere always False)."""
    path = lock_path(name, checkpoint_dir)
    try:
        import fcntl
    except ImportError:
        return False
    if not os.path.exists(path):
        return False
    try:
        fh = open(path, "a")
    except OSError:
        return False
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fh, fcntl.LOCK_UN)
        return False
    finally:
        fh.close()


def comma_list(text):
    return [t.strip() for t in (text or "").split(",") if t.strip()]


# ------------------------------------------------------------- input checks

def number(params, key):
    default, _low, _high = NUMBERS[key]
    value = str(params.get(key) or "").strip()
    return int(value) if re.fullmatch(r"\d+", value) else default


def flag(params, key):
    value = str(params.get(key, "")).strip().lower()
    if value == "":
        return bool(FLAGS[key])
    return value in ("1", "true", "yes", "on")


def mode(params, list_key):
    value = (params.get(LIST_MODE[list_key]) or "all").strip().lower()
    return value if value in MODES else "all"


def enabled_types(params):
    return [t for t in TYPES if flag(params, f"collect_{t}")]


def check_params(name, params):
    """Error message, or None when the input's settings are valid."""
    if not NAME_RE.match(name or ""):
        return "Input name: letters, digits, '.', '_' or '-' (max 64), starting with a letter or digit"
    if not NAME_RE.match(params.get("account") or ""):
        return "account: enter the name of a Secure Endpoint account saved on the add-on's Inputs page"
    for key, (default, low, high) in NUMBERS.items():
        value = str(params.get(key) or "").strip() or str(default)
        if not re.fullmatch(r"\d+", value) or not low <= int(value) <= high:
            return f"{key} must be a whole number from {low} to {high}"
    for key in FLAGS:
        value = str(params.get(key, "")).strip().lower()
        if value not in ("", "0", "1", "true", "false", "yes", "no", "on", "off"):
            return f"{key} must be 0 or 1"
    if not enabled_types(params):
        return "choose at least one data type to collect"
    if (params.get("log_level") or "INFO").upper() not in LOG_LEVELS:
        return "log_level must be one of " + ", ".join(LOG_LEVELS)
    for list_key, pattern in LISTS.items():
        mode_key = LIST_MODE[list_key]
        mode_value = (params.get(mode_key) or "all").strip().lower()
        if mode_value not in MODES:
            return f"{mode_key} must be all, only or except"
        items = comma_list(params.get(list_key))
        for item in items:
            if not pattern.match(item):
                return f"{list_key}: '{item}' is not valid (comma-separated list of IDs)"
        if mode_value != "all" and not items:
            return f"{mode_key} is {mode_value}: choose at least one in {list_key}"
    index = params.get("index") or "default"
    if not INDEX_RE.match(index):
        return "index: lowercase letters, digits, '_' or '-', starting with a letter or digit"
    return None


def read_conf_stanzas(path):
    """Splunk .conf file -> {stanza: {key: value}} (comments, continuation lines)."""
    out, stanza, pending = {}, None, None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for line in lines:
        if pending is not None:
            key, value = pending
            value += "\n" + line.rstrip("\\")
            pending = (key, value) if line.endswith("\\") else None
            out[stanza][key] = value
            continue
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("[") and text.endswith("]"):
            stanza = text[1:-1]
            out.setdefault(stanza, {})
            continue
        if stanza is not None and "=" in text:
            key, value = (part.strip() for part in text.split("=", 1))
            out[stanza][key] = value.rstrip("\\").rstrip()
            if value.endswith("\\"):
                pending = (key, out[stanza][key])
    return out


def saved_settings(name):
    """
    The input's saved settings, read from the .conf files (this app's default
    stanza, then the input's own stanza in any local/inputs.conf). Not through
    splunkd: during validation splunkd is busy with the very request being
    validated, and a call to its inputs endpoint would wait until it times out.
    """
    keep = set(SETTINGS) | {"index", "interval"}
    app_default = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "default", "inputs.conf")
    merged = dict(read_conf_stanzas(app_default).get(SCHEME, {}))
    home = splunk_home()
    paths = [os.path.join(home, "etc", "system", "local", "inputs.conf")]
    apps = os.path.join(home, "etc", "apps")
    try:
        paths += [os.path.join(apps, app, "local", "inputs.conf") for app in sorted(os.listdir(apps))]
    except OSError:
        pass
    for path in paths:
        stanzas = read_conf_stanzas(path)
        merged.update(stanzas.get(SCHEME, {}))
        merged.update(stanzas.get(f"{SCHEME}://{name}", {}))
    return {k: v for k, v in merged.items() if k in keep}


# ------------------------------------------------------------------ splunkd

class Splunkd:
    """
    Calls splunkd REST as the given session (a user's token or the modular
    input's system token). Returns (status, parsed JSON or text).
    """

    def __init__(self, token, transport=None):
        self.token = token
        self.transport = transport or _splunk_rest

    def call(self, method, path, args=None):
        if not path.startswith("/"):
            path = f"/servicesNS/nobody/{APP}/{path}"
        args = dict(args or {})
        args["output_mode"] = "json"
        status, body = self.transport(method, path, args, self.token)
        try:
            body = json.loads(body) if isinstance(body, (str, bytes)) and body else body
        except ValueError:
            pass
        return status, body

    def ok(self, method, path, args=None, allow=(200, 201)):
        status, body = self.call(method, path, args)
        if status not in allow:
            raise StoreError(error_text(body) or f"splunkd returned {status} for {path}", status)
        return body


def _splunk_rest(method, path, args, token):
    import splunk.rest               # Splunk's own Python library (present inside Splunk)
    getargs = args if method in ("GET", "DELETE") else {"output_mode": args.get("output_mode", "json")}
    postargs = None if method in ("GET", "DELETE") else {k: v for k, v in args.items() if k != "output_mode"}
    try:
        response, content = splunk.rest.simpleRequest(
            path, sessionKey=token, method=method, getargs=getargs, postargs=postargs, raiseAllErrors=False)
        return int(response.status), content
    except Exception as exc:                 # splunk.RESTException and subclasses (404, 403, ...)
        status = getattr(exc, "statusCode", None)
        if not status:
            raise
        return int(status), json.dumps(
            {"messages": [{"type": "ERROR", "text": getattr(exc, "msg", None) or str(exc)}]})


def error_text(body):
    if isinstance(body, dict):
        msgs = body.get("messages") or []
        text = "; ".join(m.get("text", "") for m in msgs if isinstance(m, dict))
        return text or body.get("error", "")
    if isinstance(body, (bytes, str)):
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        found = re.findall(r"<msg[^>]*>([^<]*)</msg>", text)
        return "; ".join(found) or text[:300]
    return ""


def entries(body):
    return body.get("entry", []) if isinstance(body, dict) else []


def quote(name):
    return urllib.parse.quote(name, safe="")


# ----------------------------------------------------------------- accounts

def check_account(doc):
    """Error message for an account's settings, or None."""
    if not api.API_HOST_RE.match(doc.get("api_host") or ""):
        return ("API host: api.amp.cisco.com (North America), api.eu.amp.cisco.com (Europe) or "
                "api.apjc.amp.cisco.com (Asia Pacific)")
    if not api.CLIENT_ID_RE.match(doc.get("client_id") or ""):
        return "Client ID: the API credential's client ID from the Secure Endpoint console (letters, digits, '-')"
    if not api.API_KEY_RE.match(doc.get("api_key") or ""):
        return "API key: the API credential's key from the Secure Endpoint console (letters, digits, '-')"
    proxy = doc.get("proxy_url") or ""
    if proxy and not api.PROXY_RE.match(proxy):
        return "Proxy: http://host:port or https://host:port (no user name or password)"
    return None


class Accounts:
    """Secure Endpoint accounts in storage/passwords, as JSON split into CHUNK-sized parts (<name>.000, ...)."""

    def __init__(self, splunkd):
        self.splunkd = splunkd

    def _parts(self):
        body = self.splunkd.ok("GET", "storage/passwords", {"count": 0, "search": f"realm={REALM}"})
        parts = {}
        for entry in entries(body):
            content = entry.get("content", {})
            if content.get("realm") != REALM:
                continue
            m = re.match(r"^(.*)\.(\d{3})$", content.get("username", ""))
            if m:
                parts.setdefault(m.group(1), {})[int(m.group(2))] = (
                    content.get("clear_password", ""), entry.get("name", ""))
        return parts

    @staticmethod
    def _assemble(chunks):
        text, i = "", 0
        while i in chunks:
            text += chunks[i][0]
            i += 1
        return json.loads(text)

    def list(self):
        """Accounts without their API keys."""
        out = []
        for name, chunks in sorted(self._parts().items()):
            try:
                doc = self._assemble(chunks)
            except ValueError:
                out.append({"name": name, "error": "stored account is incomplete; save it again"})
                continue
            client_id = doc.get("client_id", "")
            out.append({"name": name, "api_host": doc.get("api_host", ""), "proxy_url": doc.get("proxy_url", ""),
                        "client_id_hint": ("..." + client_id[-6:]) if len(client_id) > 6 else client_id,
                        "saved": doc.get("saved", ""), "saved_by": doc.get("saved_by", "")})
        return out

    def get(self, name):
        chunks = self._parts().get(name)
        if not chunks:
            raise StoreError(f"Secure Endpoint account '{name}' is not saved", 404)
        try:
            return self._assemble(chunks)
        except ValueError:
            raise StoreError(f"Secure Endpoint account '{name}' is incomplete; save it again", 500)

    def save(self, name, doc, user=""):
        """Creates or replaces an account. Empty client_id / api_key keep the saved ones."""
        if not NAME_RE.match(name or ""):
            raise StoreError("Account name: letters, digits, '.', '_' or '-' (max 64), starting with a letter or digit")
        current = {}
        if name in self._parts():
            current = self.get(name)
        merged = {
            "api_host": (doc.get("api_host") or current.get("api_host") or "").strip().lower(),
            "client_id": (doc.get("client_id") or current.get("client_id") or "").strip(),
            "api_key": (doc.get("api_key") or current.get("api_key") or "").strip(),
            "proxy_url": (doc.get("proxy_url") if doc.get("proxy_url") is not None
                          else current.get("proxy_url", "")) or "",
        }
        merged["proxy_url"] = merged["proxy_url"].strip()
        problem = check_account(merged)
        if problem:
            raise StoreError(problem)
        merged["saved"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        merged["saved_by"] = user or ""
        text = json.dumps(merged, separators=(",", ":"))
        chunks = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)]
        existing = self._parts().get(name, {})
        # Parts are updated in place (never deleted first), so the account stays readable while it is saved.
        for i, part in enumerate(chunks):
            if i in existing:
                self.splunkd.ok("POST", f"storage/passwords/{quote(existing[i][1])}", {"password": part})
            else:
                self.splunkd.ok("POST", "storage/passwords",
                                {"name": f"{name}.{i:03d}", "realm": REALM, "password": part})
        for i, (_, entry_name) in existing.items():
            if i >= len(chunks):
                self.splunkd.ok("DELETE", f"storage/passwords/{quote(entry_name)}", allow=(200, 404))
        return {"name": name, "api_host": merged["api_host"], "proxy_url": merged["proxy_url"]}

    def delete(self, name, missing_ok=False):
        chunks = self._parts().get(name)
        if not chunks:
            if missing_ok:
                return
            raise StoreError(f"Secure Endpoint account '{name}' not found", 404)
        for _, entry_name in chunks.values():
            self.splunkd.ok("DELETE", f"storage/passwords/{quote(entry_name)}", allow=(200, 404))


def client_for(account, **kwargs):
    return api.Client(account["api_host"], account["client_id"], account["api_key"],
                      account.get("proxy_url") or "", **kwargs)


# ------------------------------------------------------------------ status

RUN_RE = re.compile(r"run (?P<result>done|failed|skipped|stopped): (?P<detail>.*)$")
TYPE_RE = re.compile(r"^(?P<what>collected|failed) (?P<type>[a-z]+): (?P<detail>.*)$")
LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} (?P<level>[A-Z]+) (?P<msg>.*)$")
BEHIND_RE = re.compile(r"behind (?P<behind>-?[\d.]+) min")
WRITTEN_RE = re.compile(r"written (?P<count>\d+)")


def read_status(name):
    """
    Latest run, and the latest result per data type, from the input's own log file on this instance
    (works without local indexing): {"result", "detail", "last_run", "types": {type: {...}}}.
    """
    try:
        with open(log_path(name), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 262144))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return {}
    out = {"types": {}}
    for line in reversed(lines):
        m = LINE_RE.match(line)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        out.setdefault("last_seen", ts)
        msg = m.group("msg")
        run = RUN_RE.search(msg)
        if run and run.group("result") != "skipped" and "result" not in out:
            out["result"] = run.group("result")
            out["detail"] = run.group("detail")
            out["last_run"] = ts
        typed = TYPE_RE.match(msg)
        if typed and typed.group("type") not in out["types"]:
            item = {"result": "done" if typed.group("what") == "collected" else "failed",
                    "detail": typed.group("detail"), "last": ts}
            count = WRITTEN_RE.search(typed.group("detail"))
            if count:
                item["count"] = count.group("count")
            behind = BEHIND_RE.search(typed.group("detail"))
            if behind:
                item["behind"] = behind.group("behind")
            out["types"][typed.group("type")] = item
        if "result" in out and len(out["types"]) >= len(TYPES):
            break
    return out
