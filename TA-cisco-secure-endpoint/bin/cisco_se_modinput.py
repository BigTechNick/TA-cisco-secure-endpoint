# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_se_modinput.py - modular input plumbing: the scheme splunkd asks for,
splunkd's XML configuration, validation, the input's log file, a lock so one
run per input at a time, and the XML event stream to splunkd.
"""
import errno
import json
import logging
import logging.handlers
import os
import re
import signal
import sys
import xml.etree.ElementTree as ElementTree
from xml.sax.saxutils import escape as xml_escape

import cisco_se_store as store

LOG_MAX_BYTES = 10 << 20          # 10 MB, 3 old copies kept
LOG_KEEP = 3

# Characters XML 1.0 does not allow (the event stream to splunkd is XML).
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")


# ------------------------------------------------------------------ scheme

def print_scheme(title, description, args):
    """args: (name, title, description, data_type, required_on_create)"""
    rows = []
    for name, arg_title, desc, kind, required in args:
        rows.append(
            f'      <arg name="{name}">\n'
            f"        <title>{xml_escape(arg_title)}</title>\n"
            f"        <description>{xml_escape(desc)}</description>\n"
            f"        <data_type>{kind}</data_type>\n"
            f"        <required_on_create>{str(required).lower()}</required_on_create>\n"
            f"        <required_on_edit>false</required_on_edit>\n"
            f"      </arg>")
    print(f"""<scheme>
  <title>{xml_escape(title)}</title>
  <description>{xml_escape(description)}</description>
  <use_external_validation>true</use_external_validation>
  <use_single_instance>false</use_single_instance>
  <streaming_mode>xml</streaming_mode>
  <endpoint>
    <args>
{chr(10).join(rows)}
    </args>
  </endpoint>
</scheme>""")


def read_config(text, scheme):
    """splunkd's XML (run or validate) -> dict with session info and [(name, params)]."""
    root = ElementTree.fromstring(text)
    cfg = {k: (root.findtext(k) or "") for k in ("server_host", "server_uri", "session_key", "checkpoint_dir")}
    stanzas = []
    for node in root.iter():
        if node.tag in ("stanza", "item"):
            name = node.get("name", "")
            if name.startswith(scheme + "://"):
                name = name[len(scheme) + 3:]
            params = {p.get("name"): (p.text or "").strip() for p in node.findall("param")}
            stanzas.append((name, params))
    cfg["stanzas"] = stanzas
    return cfg


def validate(text):
    """--validate-arguments: prints splunkd's error XML and exits 1 when the settings are not valid."""
    cfg = read_config(text, store.SCHEME)
    error = None
    for name, params in cfg["stanzas"]:
        # On an edit splunkd passes only the settings being changed: check them with the saved ones.
        params = {**store.saved_settings(name), **{k: v for k, v in params.items() if v != ""}}
        error = store.check_params(name, params)
        if not error and cfg["session_key"]:
            try:
                store.Accounts(store.Splunkd(cfg["session_key"])).get(params["account"])
            except store.StoreError as exc:
                if exc.status == 404:
                    error = f"{exc} - save it on the add-on's Inputs page first"
            except Exception:                           # credential store unreachable: don't block the edit
                pass
        if error:
            break
    if error:
        print(f"<error><message>{xml_escape(error)}</message></error>")
        sys.exit(1)


# ------------------------------------------------------------------ logging

def setup_logging(name, level):
    path = store.log_path(name)
    log = logging.getLogger(f"cisco_se.{name}")
    log.handlers[:] = []
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_KEEP,
                                                       encoding="utf-8")
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(level)
    log.propagate = False
    return log


# ------------------------------------------------------------------ lock

class RunLock:
    """One run per input at a time (a second one exits). POSIX only; elsewhere splunkd's own scheduling."""

    def __init__(self, path):
        self.path = path
        self.fh = None

    def acquire(self):
        try:
            import fcntl
        except ImportError:
            return True
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.fh.close()
            self.fh = None
            return False


class Stopper:
    """SIGTERM / SIGINT (splunkd stopping or disabling the input): finish the current page, then stop."""

    def __init__(self):
        self.stopping = False
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._stop)
            except (ValueError, OSError):
                pass

    def _stop(self, _sig, _frame):
        self.stopping = True

    def __call__(self):
        return self.stopping


# ------------------------------------------------------------------ output

class OutputClosed(Exception):
    """splunkd stopped reading the events (input disabled or restarted, Run now, or Splunk stopping)."""


def _pipe_gone(exc):
    return isinstance(exc, BrokenPipeError) or (isinstance(exc, OSError) and exc.errno in (errno.EPIPE, errno.EBADF))


class EventStream:
    """
    XML events to splunkd on stdout (streaming_mode xml): one <event> per record.
    When splunkd closes the pipe, write() and flush() raise OutputClosed and `closed` is True; close()
    never raises (it runs in finally blocks).
    """

    def __init__(self, out=None):
        self.out = out or sys.stdout.buffer
        self.started = False
        self.closed = False
        self.count = 0
        self.bytes = 0

    def _lost(self):
        self.closed = True
        # Python flushes stdout once more at exit: send that to /dev/null instead of a closed pipe.
        try:
            fd = os.open(os.devnull, os.O_WRONLY)
            os.dup2(fd, self.out.fileno())
            os.close(fd)
        except (OSError, ValueError, AttributeError):
            pass

    def _put(self, raw, flush=False):
        if self.closed:
            raise OutputClosed()
        try:
            if raw:
                self.out.write(raw)
            if flush:
                self.out.flush()
        except OSError as exc:
            if not _pipe_gone(exc):
                raise
            self._lost()
            raise OutputClosed() from exc

    def write(self, record, epoch, sourcetype, host):
        if not self.started:
            self._put(b"<stream>\n")
            self.started = True
        # json.dumps defaults (", " and ": ", ASCII), the way the Cisco Security Cloud app writes cisco:se
        data = _BAD_XML.sub("\ufffd", json.dumps(record))
        chunk = (f"<event><time>{epoch:.3f}</time><host>{xml_escape(host)}</host>"
                 f"<sourcetype>{xml_escape(sourcetype)}</sourcetype><data>{xml_escape(data)}</data></event>\n")
        self._put(chunk.encode("utf-8", "replace"))
        self.count += 1
        self.bytes += len(data)

    def flush(self):
        self._put(b"", flush=True)

    def close(self):
        if self.closed:
            return
        try:
            self._put(b"</stream>\n" if self.started else b"", flush=True)
        except OutputClosed:
            pass
        except OSError:
            self.closed = True


# ------------------------------------------------------------------ state

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else default
    except (OSError, ValueError):
        return default


def save_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
    os.replace(tmp, path)


# ------------------------------------------------------------------ main

def main(title, description, args, run):
    if len(sys.argv) > 1 and sys.argv[1] == "--scheme":
        print_scheme(title, description, args)
    elif len(sys.argv) > 1 and sys.argv[1] == "--validate-arguments":
        validate(sys.stdin.read())
    else:
        cfg = read_config(sys.stdin.read(), store.SCHEME)
        if not cfg["stanzas"]:
            return
        name, params = cfg["stanzas"][0]
        error = store.check_params(name, params)
        if error:
            sys.stderr.write(f"{store.SCHEME}://{name}: {error}\n")      # lands in splunkd.log
            sys.exit(1)
        sys.exit(run(cfg, name, params) or 0)
