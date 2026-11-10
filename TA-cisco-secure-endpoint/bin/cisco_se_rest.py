# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_se_rest.py - REST API behind the add-on's Inputs page.

  /services/cisco_se/inputs
      GET                                  inputs, account names, indexes
      POST action=create|edit              name, input settings
      POST action=enable|disable|run|delete   name
  /services/cisco_se/accounts
      GET                                  saved accounts (never the API key)
      POST action=save                     name, api_host, client_id, api_key, proxy_url
                                           (empty client_id / api_key keep the saved ones)
      POST action=test                     name: one small call for events and one for audit logs
      POST action=delete                   name
  /services/cisco_se/options
      GET account=<name>                   event types, audit log types and groups, live from the API,
                                           for the Inputs page's lists

Every change is made with the signed-in user's own session, so Splunk's
normal permissions apply (admin rights to change inputs and the credential
store). Accounts are stored encrypted in Splunk's credential store.
"""
import json
import logging
import logging.handlers
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cisco_se_api as api  # noqa: E402
import cisco_se_store as store  # noqa: E402
from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

FIELDS = store.SETTINGS + ("index", "interval")
INPUTS_PATH = f"data/inputs/{store.SCHEME}"
DEFAULT_INTERVAL = "60"


def get_logger():
    log = logging.getLogger("cisco_se_rest")
    if not log.handlers:
        path = os.path.join(store.splunk_home(), "var", "log", "splunk", "cisco_se-webapi.log")
        try:
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=5 << 20, backupCount=2)
        except OSError:
            handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def form_of(req):
    form = {}
    for key in ("query", "form"):
        for pair in req.get(key) or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                form[pair[0]] = pair[1]
    payload = req.get("payload")
    if not req.get("form") and isinstance(payload, str) and payload:
        try:
            form.update(json.loads(payload))
        except ValueError:
            form.update({k: v[-1] for k, v in urllib.parse.parse_qs(payload, keep_blank_values=True).items()})
    return form


def reply(payload, status=200):
    return {"payload": payload, "status": status}


class Api:
    def __init__(self, splunkd, user, log):
        self.splunkd, self.user, self.log = splunkd, user, log
        self.accounts = store.Accounts(splunkd)

    # ---- inputs
    def inputs(self):
        out = []
        body = self.splunkd.ok("GET", INPUTS_PATH, {"count": 0}, allow=(200,))
        for entry in store.entries(body):
            content = entry.get("content", {})
            item = {k: content.get(k, "") for k in FIELDS}
            for key in store.FLAGS:
                item[key] = "1" if store.flag(content, key) else "0"
            item.update(name=entry.get("name"), disabled=content.get("disabled") in (True, "1", 1, "true"),
                        status=store.read_status(entry.get("name")))
            out.append(item)
        out.sort(key=lambda i: i["name"].lower())
        return out

    def get_inputs(self):
        indexes = []
        status, body = self.splunkd.call("GET", "/services/data/indexes", {"count": 0, "datatype": "event"})
        if status == 200:
            indexes = sorted(e.get("name") for e in store.entries(body)
                             if not e.get("content", {}).get("disabled"))
        names = []
        try:
            names = [a["name"] for a in self.accounts.list()]
        except store.StoreError as exc:
            self.log.warning("listing accounts failed: %s", exc)
        return {"inputs": self.inputs(), "accounts": names, "indexes": indexes,
                "types": {t: {"label": spec[0], "on": spec[1], "every": spec[2], "low": spec[3], "high": spec[4]}
                          for t, spec in store.TYPES.items()}}

    def find(self, name, inputs=None):
        for item in inputs if inputs is not None else self.inputs():
            if item["name"] == name:
                return item
        raise store.StoreError(f"input '{name}' not found", 404)

    def check_overlap(self, name, settings, inputs):
        """Two inputs collecting the same data type from the same account would index it twice."""
        mine = set(store.enabled_types(settings))
        for other in inputs:
            if other["name"] == name or other["account"] != settings.get("account"):
                continue
            both = mine & set(store.enabled_types(other))
            if both:
                labels = ", ".join(store.TYPES[t][0].lower() for t in store.TYPES if t in both)
                raise store.StoreError(f"input '{other['name']}' already collects {labels} from account "
                                       f"'{other['account']}'; each data type once per account (or the data is "
                                       "indexed twice)")

    def post_inputs(self, form):
        action = form.get("action", "")
        name = (form.get("name") or "").strip()
        if not store.NAME_RE.match(name):
            raise store.StoreError("Input name: letters, digits, '.', '_' or '-' (max 64), "
                                   "starting with a letter or digit")
        path = f"{INPUTS_PATH}/{store.quote(name)}"
        if action in ("create", "edit"):
            args = {k: str(form[k]).strip() for k in FIELDS if k in form}
            inputs = self.inputs()
            if action == "create":
                if any(i["name"] == name for i in inputs):
                    raise store.StoreError(f"an input named '{name}' already exists")
                args["interval"] = args.get("interval") or DEFAULT_INTERVAL
                self.check_interval(args["interval"])
                problem = store.check_params(name, args)
                if problem:
                    raise store.StoreError(problem)
                self.check_overlap(name, args, inputs)
                self.splunkd.ok("POST", INPUTS_PATH, dict(args, name=name))
            else:
                current = self.find(name, inputs)
                if "interval" in args:
                    args["interval"] = args["interval"] or DEFAULT_INTERVAL
                    self.check_interval(args["interval"])
                merged = {k: v for k, v in current.items() if k in FIELDS}
                merged.update(args)
                problem = store.check_params(name, merged)
                if problem:
                    raise store.StoreError(problem)
                self.check_overlap(name, merged, inputs)
                self.splunkd.ok("POST", path, args)
                if not current["disabled"]:             # restart with the new settings
                    self.restart(path)
        elif action in ("enable", "disable"):
            self.splunkd.ok("POST", f"{path}/{action}")
        elif action == "run":
            current = self.find(name)
            if current["disabled"]:
                raise store.StoreError(f"input '{name}' is disabled; enable it first")
            if store.run_in_progress(name):          # Run now restarts the input: it would stop that run
                raise store.StoreError(f"a run of input '{name}' is in progress; Run now would stop it. "
                                       "Try again when it has finished.", 409)
            marker = store.run_now_path(name)
            os.makedirs(os.path.dirname(marker), exist_ok=True)
            with open(marker, "w") as fh:
                fh.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            self.restart(path)                        # with the user's own rights
        elif action == "delete":
            self.find(name)
            self.splunkd.ok("DELETE", path)
            for leftover in (store.state_path(name), store.run_now_path(name), store.lock_path(name)):
                try:
                    os.remove(leftover)
                except OSError:
                    pass
        else:
            raise store.StoreError("action must be create, edit, enable, disable, run or delete")
        self.log.info("user=%s input=%s action=%s", self.user, name, action)
        return {"ok": True, "inputs": self.inputs()}

    @staticmethod
    def check_interval(value):
        value = str(value).strip()
        if not value.isdigit() or not 60 <= int(value) <= 3600:
            raise store.StoreError("interval: seconds from 60 to 3600 (how often Splunk starts the input; each data "
                                   "type has its own schedule)")

    def restart(self, path):
        self.splunkd.ok("POST", f"{path}/disable")
        self.splunkd.ok("POST", f"{path}/enable")

    # ---- accounts
    def get_accounts(self):
        accounts = self.accounts.list()
        try:
            used = {}
            for item in self.inputs():
                used.setdefault(item["account"], []).append(item["name"])
            for account in accounts:
                account["used_by"] = used.get(account["name"], [])
        except store.StoreError:
            pass
        return {"accounts": accounts}

    def post_accounts(self, form):
        action = form.get("action", "")
        name = (form.get("name") or "").strip()
        if action == "save":
            doc = {k: form.get(k) for k in ("api_host", "client_id", "api_key", "proxy_url")}
            saved = self.accounts.save(name, doc, self.user)
            self.log.info("user=%s account=%s action=save api_host=%s proxy=%s", self.user, name,
                          saved["api_host"], "yes" if saved["proxy_url"] else "no")
            return {"ok": True, "account": saved}
        if action == "test":
            result = self.test(self.accounts.get(name))
            self.log.info("user=%s account=%s action=test result=%s", self.user, name,
                          "ok" if result["ok"] else "failed")
            return result
        if action == "delete":
            users = [i["name"] for i in self.inputs() if i["account"] == name]
            if users:
                raise store.StoreError(f"'{name}' is used by input(s) {', '.join(users)}; "
                                       "change or delete them first")
            self.accounts.delete(name)
            self.log.info("user=%s account=%s action=delete", self.user, name)
            return {"ok": True}
        raise store.StoreError("action must be save, test or delete")

    @staticmethod
    def test(account):
        """One small call for events and one for audit logs: is the credential accepted, and may it read them?"""
        checks = {}
        try:   # two calls of at most 12 s: an answer within Splunk Web's 30 s
            client = store.client_for(account, timeout=12, max_attempts=1)
        except api.ApiError as exc:
            return {"ok": False, "checks": {"account": str(exc)}, "api_host": account.get("api_host", "")}
        for label, path in (("events", "/v1/events"), ("audit_logs", "/v1/audit_logs")):
            if any(str(v).startswith("cannot reach") or "could not be verified" in str(v) for v in checks.values()):
                checks[label] = "not tried (see above)"
                continue
            try:
                client.get(path, {"limit": 1})
                checks[label] = "OK"
            except api.ApiError as exc:
                checks[label] = str(exc)
            except Exception as exc:
                checks[label] = f"{type(exc).__name__}: {exc}"
        return {"ok": all(v == "OK" for v in checks.values()), "checks": checks, "api_host": account["api_host"]}

    # ---- options for the Inputs page's lists
    def get_options(self, form):
        name = (form.get("account") or "").strip()
        client = store.client_for(self.accounts.get(name), timeout=12, max_attempts=1)
        out, errors = {"event_types": [], "audit_types": [], "groups": []}, {}
        for records, _ in self._pages(client, "/v1/event_types", None, errors, "event_types"):
            for r in records:
                if r.get("id") is not None:
                    out["event_types"].append({"id": str(r["id"]), "name": r.get("name") or "",
                                               "description": r.get("description") or ""})
        for records, _ in self._pages(client, "/v1/audit_log_types", None, errors, "audit_types"):
            for r in records:
                if r.get("id"):
                    out["audit_types"].append({"id": str(r["id"]), "name": r.get("name") or ""})
        for records, _ in self._pages(client, "/v1/groups", {"limit": 100}, errors, "groups"):
            for r in records:
                if r.get("guid"):
                    out["groups"].append({"id": r["guid"], "name": r.get("name") or "",
                                          "description": r.get("description") or ""})
        for key in out:
            out[key].sort(key=lambda o: ((o.get("name") or "~").lower(), o["id"]))
        out["errors"] = errors
        return out

    @staticmethod
    def _pages(client, path, params, errors, key):
        try:
            for item in client.pages(path, params, max_pages=50):
                yield item
        except api.ApiError as exc:
            errors[key] = str(exc)


class Handler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        PersistentServerConnectionApplication.__init__(self)
        self.log = get_logger()

    def handle(self, in_string):
        try:
            req = json.loads(in_string)
            session = req.get("session") or {}
            handler = Api(store.Splunkd(session.get("authtoken")), session.get("user", ""), self.log)
            method = (req.get("method") or "GET").upper()
            path = (req.get("rest_path") or "").rstrip("/")
            form = form_of(req)
            if method == "DELETE":
                method, form["action"] = "POST", "delete"
            if path.endswith("/inputs"):
                return reply(handler.get_inputs() if method == "GET" else handler.post_inputs(form))
            if path.endswith("/accounts"):
                return reply(handler.get_accounts() if method == "GET" else handler.post_accounts(form))
            if path.endswith("/options") and method == "GET":
                return reply(handler.get_options(form))
            return reply({"error": f"unknown path {path}"}, 404)
        except store.StoreError as exc:
            return reply({"error": str(exc)}, exc.status if 400 <= exc.status < 600 else 400)
        except api.ApiError as exc:
            return reply({"error": str(exc)}, 502)
        except Exception as exc:                                    # keep the handler alive
            self.log.exception("request failed")
            return reply({"error": f"{type(exc).__name__}: {exc}"}, 500)
