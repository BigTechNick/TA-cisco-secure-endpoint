# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
cisco_se_api.py - client for the Cisco Secure Endpoint API v1 (formerly AMP for Endpoints).

Every call is an HTTPS GET with Basic authentication (the API client ID and
API key from the Secure Endpoint console, Administration > API Credentials,
read-only scope is enough).

  * Client.get(): one call, with retries for rate limits (429), server errors
    and network errors
  * Client.pages(): a list endpoint page by page (metadata.links.next)
  * iso() / parse_time(): the API's ISO 8601 timestamps

Standard library only; runs on Splunk's bundled Python 3.9 and 3.13.
"""
import base64
import calendar
import http.client
import json
import os
import random
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

APP_VERSION = "1.0.0"
USER_AGENT = f"TA-cisco-secure-endpoint/{APP_VERSION}"

# Secure Endpoint cloud API hosts: api.amp.cisco.com (North America) and api.<region>.amp.cisco.com
# (api.eu.amp.cisco.com, api.apjc.amp.cisco.com).
API_HOST_RE = re.compile(r"^api(?:\.[a-z0-9-]{1,20})?\.amp\.cisco\.com$")
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
API_KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
PROXY_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(?::\d{1,5})?/?$")

RETRY_STATUS = (408, 425, 429, 500, 502, 503, 504)
MAX_ATTEMPTS = 6
MAX_WAIT = 600
MAX_PAGES = 20000


class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ time

def iso(epoch):
    """2026-11-03T20:32:30+00:00 (whole seconds, UTC), as the API documents its date filters."""
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(int(epoch)))


ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(text):
    """2026-11-03T20:32:30+00:00, 2026-11-03T20:32:09Z, ...000Z -> epoch seconds, or None."""
    m = ISO_RE.match((text or "").strip()) if isinstance(text, str) else None
    if not m:
        return None
    parts = [int(x) for x in m.groups()[:6]]
    try:
        epoch = calendar.timegm((parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], 0, 0, 0))
    except (OverflowError, ValueError):
        return None
    epoch += float("0." + (m.group(7) or "0"))
    zone = m.group(8)
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        epoch -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    return epoch


# ------------------------------------------------------------------ http

def ssl_context():
    """System CAs, plus the bundle that ships with Splunk's Python (certifi) and common system bundles."""
    ctx = ssl.create_default_context()
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    extra = []
    try:
        import certifi
        extra.append(certifi.where())
    except Exception:
        pass
    extra += ["/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"]
    for path in extra:
        if path and os.path.isfile(path):
            try:
                ctx.load_verify_locations(cafile=path)
            except (ssl.SSLError, OSError):
                pass
    return ctx


def error_message(status, body):
    """Short message from an API error response ({"errors": [{"description": ..., "details": [...]}]})."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            errors = doc.get("errors")
            if isinstance(errors, list) and errors:
                parts = []
                for err in errors[:3]:
                    if isinstance(err, dict):
                        detail = err.get("details")
                        detail = "; ".join(str(d) for d in detail) if isinstance(detail, list) else (detail or "")
                        parts.append(" - ".join(p for p in (str(err.get("description") or ""), detail) if p))
                if any(parts):
                    return f"HTTP {status}: " + " | ".join(p for p in parts if p)[:300]
            for key in ("message", "error", "description"):
                if doc.get(key):
                    return f"HTTP {status}: {str(doc[key])[:300]}"
    except ValueError:
        pass
    text = " ".join(text.split())
    return f"HTTP {status}: {text[:300]}" if text else f"HTTP {status}"


HINTS = {
    401: "the API client ID or API key was not accepted (wrong value, or the credential was deleted)",
    403: "the API credential lacks permission for this data",
    404: "this API path is not available for the organization or region",
}


def _wait_from(headers):
    """Seconds to wait from Retry-After or X-RateLimit-Reset, or None."""
    if not headers:
        return None
    for name in ("Retry-After", "X-RateLimit-Reset", "X-Ratelimit-Reset"):
        value = headers.get(name)
        if value and value.strip().isdigit():
            return min(max(int(value.strip()), 1), MAX_WAIT)
    return None


class Client:
    """
    One Secure Endpoint organization: API host, client ID, API key, optional HTTPS proxy.
    should_stop: a function; when it returns True, retries and waits end early.
    """

    def __init__(self, api_host, client_id, api_key, proxy_url="", timeout=120, log=None,
                 should_stop=None, max_attempts=MAX_ATTEMPTS):
        if not API_HOST_RE.match(api_host or ""):
            raise ApiError(f"API host {api_host!r} is not a Secure Endpoint API host (api[.<region>].amp.cisco.com)")
        self.api_host = api_host
        self.timeout = timeout
        self.log = log
        self.should_stop = should_stop or (lambda: False)
        self.max_attempts = max_attempts
        self.calls = 0
        self.retries = 0
        self.rate_remaining = None
        token = base64.b64encode(f"{client_id}:{api_key}".encode("utf-8")).decode("ascii")
        self._auth = f"Basic {token}"
        handlers = [urllib.request.HTTPSHandler(context=self.make_ssl_context())]
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url}))
        self.opener = urllib.request.build_opener(*handlers)

    # Tests point these at a local server.
    def base_url(self):
        return f"https://{self.api_host}"

    def make_ssl_context(self):
        return ssl_context()

    def url_for(self, path, params=None):
        """A path (/v1/events) plus query, or a next-page URL from the API (same host and /v1/ only)."""
        if path.startswith("https://") or path.startswith("http://"):
            want = urllib.parse.urlparse(self.base_url())
            got = urllib.parse.urlparse(path)
            if got.scheme != want.scheme or got.netloc.lower() != want.netloc.lower() or \
                    not got.path.startswith("/v1/"):
                raise ApiError(f"the API returned a next page on another host or path ({got.netloc}{got.path}); "
                               "stopping")
            return path
        query = urllib.parse.urlencode(params or {}, doseq=True)
        return self.base_url() + path + ("?" + query if query else "")

    def _sleep(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            if self.should_stop():
                raise ApiError("stopped")
            time.sleep(min(1.0, max(0.0, end - time.time())))

    def get(self, path, params=None):
        """GET path?params (or a full next-page URL); returns the parsed JSON body (dict or list)."""
        url = self.url_for(path, params)
        label = urllib.parse.urlparse(url).path
        attempt = 0
        while True:
            attempt += 1
            if self.should_stop():
                raise ApiError("stopped")
            req = urllib.request.Request(url, method="GET", headers={
                "Authorization": self._auth, "Accept": "application/json", "User-Agent": USER_AGENT})
            status, payload, wait = None, b"", None
            self.calls += 1
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    status = resp.status
                    payload = resp.read()           # IncompleteRead (HTTPException) is retried below
                    remaining = resp.headers.get("X-RateLimit-Remaining") if resp.headers else None
                    if remaining and remaining.strip().isdigit():
                        self.rate_remaining = int(remaining.strip())
            except urllib.error.HTTPError as exc:
                status = exc.code
                try:
                    payload = exc.read()
                except Exception:
                    payload = b""
                wait = _wait_from(exc.headers)
            except (urllib.error.URLError, http.client.HTTPException, socket.timeout, ConnectionError, ssl.SSLError,
                    OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
                    raise ApiError(f"TLS certificate of {self.api_host} could not be verified ({reason}). "
                                   "If a proxy inspects TLS, add its CA to the system CA bundle.")
                message = f"cannot reach {self.api_host}: {reason}"
                if attempt >= self.max_attempts:
                    raise ApiError(message)
                self._retry(attempt, message, None)
                continue

            if status == 200:
                try:
                    return json.loads(payload.decode("utf-8")) if payload.strip() else {}
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ApiError(f"response from {label} is not JSON ({exc})", status)
            message = error_message(status, payload)
            if status in RETRY_STATUS and attempt < self.max_attempts:
                self._retry(attempt, message, wait)
                continue
            if status in HINTS:
                message += f" - {HINTS[status]}"
            raise ApiError(f"{label}: {message}", status)

    def _retry(self, attempt, message, wait):
        if wait is None:
            wait = min(2 ** attempt * 2, 120) + random.uniform(0, 2)
        self.retries += 1
        if self.log:
            self.log.warning("%s - retry %d of %d in %.0f s", message, attempt, self.max_attempts - 1, wait)
        self._sleep(wait)

    def pages(self, path, params=None, max_pages=MAX_PAGES):
        """
        A list endpoint page by page, following metadata.links.next. Yields (records, page number).
        A bare JSON list (some endpoints answer [] when there is nothing) is one page.
        """
        url, page, seen = path, 0, set()
        query = params
        while True:
            page += 1
            doc = self.get(url, query)
            records = records_of(doc)
            yield records, page
            nxt = next_link(doc)
            if not nxt or not records:
                return
            if nxt in seen:
                raise ApiError(f"{path}: the API returned the same next page twice (page {page}); stopping")
            if page >= max_pages:
                raise ApiError(f"{path}: more than {max_pages} pages; stopping")
            seen.add(nxt)
            url, query = nxt, None


def records_of(doc):
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    data = doc.get("data") if isinstance(doc, dict) else None
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def next_link(doc):
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    links = meta.get("links") if isinstance(meta, dict) else None
    value = links.get("next") if isinstance(links, dict) else None
    return value if isinstance(value, str) and value else ""


def total_of(doc):
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    results = meta.get("results") if isinstance(meta, dict) else None
    value = results.get("total") if isinstance(results, dict) else None
    return value if isinstance(value, int) else None
