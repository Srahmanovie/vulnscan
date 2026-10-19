#!/usr/bin/env python3
"""
Active scanning for vulnscan.

Only enabled with `--active` AND `--i-have-authorization`.

This module does:
  * directory / file brute forcing (wordlist-driven)
  * non-destructive verification probes for reflected XSS, open redirect,
    local file inclusion, and basic SSRF

It does NOT do exploitation, data extraction, or payload delivery.
"""

import os
import random
import secrets
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, urljoin, urlparse, urlsplit, urlunsplit, parse_qsl

import requests


# ---------- per-host rate limiting ----------

class HostThrottle:
    """Rate limit per hostname so multi-target scans don't stack globally."""
    def __init__(self, interval):
        self.interval = interval
        self._lock = threading.Lock()
        self._last = {}

    def wait(self, host):
        with self._lock:
            now = time.monotonic()
            nxt = self._last.get(host, 0) + self.interval
            if nxt > now:
                time.sleep(nxt - now)
            self._last[host] = time.monotonic()


# ---------- directory brute forcing ----------

DEFAULT_WORDLIST = [
    # control-panel-ish
    "admin", "admin/", "administrator", "login", "console", "dashboard",
    "manager", "portal", "cp", "cpanel", "phpmyadmin",
    # common app frameworks
    "api", "api/v1", "api/v2", "graphql", "swagger-ui.html", "swagger.json",
    "openapi.json", "actuator", "actuator/health", "actuator/env",
    "api-docs", "redoc", ".well-known/security.txt",
    # backups / dumps
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "data.sql", "site.zip", "www.zip", "old/", "dev/",
    # config / metadata
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    ".svn/entries", ".hg/", ".DS_Store", "config.php", "config.php.bak",
    "wp-config.php.bak", "web.config.bak", "composer.json", "package.json",
    # common uploads / logs
    "uploads/", "files/", "logs/", "log/", "tmp/", "temp/",
    "access.log", "error.log", "debug.log",
    # common endpoints
    "robots.txt", "sitemap.xml", "security.txt", "humans.txt",
    "health", "healthz", "status", "metrics", "server-status",
    # misc
    "test", "test/", "staging/", "demo/", "wp-admin/", "wp-login.php",
]


def load_wordlist(path, extra_builtin=True):
    if path:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if extra_builtin:
        return list(DEFAULT_WORDLIST)
    return []


def _soft_404_baseline(session, base_url, timeout):
    """Fetch a guaranteed-nonexistent path to calibrate 200-for-everything servers."""
    probe = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
    r = session.get(urljoin(base_url, probe), timeout=timeout, allow_redirects=False)
    return r.status_code, len(r.content), r.text[:4096]


def brute_force(report, session, base_url, wordlist, timeout=8.0,
                max_workers=6, rate_interval=0.20, follow_redirects=False,
                interesting_codes=(200, 204, 301, 302, 303, 307, 308, 401, 403)):
    section = "Directory/File Brute Force"
    host = urlparse(base_url).hostname
    throttle = HostThrottle(rate_interval)

    try:
        b_status, b_len, b_text = _soft_404_baseline(session, base_url, timeout)
    except requests.RequestException as e:
        report.add(section, "ERROR", "baseline", str(e))
        return

    def is_soft_404(resp):
        # Same status AND similar length AND similar body prefix -> catch-all.
        if resp.status_code != b_status:
            return False
        if abs(len(resp.content) - b_len) > max(80, int(b_len * 0.05)):
            return False
        return resp.text[:4096] == b_text

    def probe(word):
        throttle.wait(host)
        path = "/" + word.lstrip("/")
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=follow_redirects)
        except requests.RequestException as e:
            return ("error", path, str(e))

        if r.status_code in interesting_codes and not is_soft_404(r):
            return ("hit", path, r.status_code, len(r.content),
                    r.headers.get("Content-Type", "").split(";")[0])
        return None

    hits, errors = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, w): w for w in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            if res[0] == "error":
                errors.append(res)
            else:
                _, path, status, length, ctype = res
                hits.append((path, status, length, ctype))

    if hits:
        for path, status, length, ctype in sorted(hits, key=lambda x: (x[0], x[1])):
            severity = "FOUND" if status in (200, 204) else "INFO"
            detail = f"{status}, {length}B"
            if ctype:
                detail += f", {ctype}"
            report.add(section, severity, path, detail)
    else:
        report.add(section, "OK", "no interesting paths",
                   f"tested {len(wordlist)} candidates")

    if errors:
        report.add(section, "ERROR", "probe errors",
                   f"{len(errors)} failed; first: {errors[0][1]} -> {errors[0][2][:80]}")

    report.set_meta("bruteforce_tested", len(wordlist))
    report.set_meta("bruteforce_hits", len(hits))


# ---------- non-destructive verification probes ----------

def _mutate_query(url, param, value):
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q), parts.fragment))


def _candidate_reflecting_urls(session, url, timeout):
    """Yield GET URLs with query params that might reflect input."""
    parsed = urlparse(url)
    if parsed.query:
        yield url
    # Also try a few common patterns even if the input URL has no params.
    for p in ("q", "s", "search", "query", "id", "page", "name", "lang", "next", "url"):
        sep = "&" if urlparse(url).query else "?"
        yield f"{url}{sep}{p}=test"


def verify_reflected_xss(report, session, url, timeout=8.0):
    """Detect reflected XSS by sending a safe marker and checking the echo is
    NOT HTML-encoded. Does not execute anything; does not use event handlers."""
    section = "XSS (reflection check)"
    marker = "vs" + secrets.token_hex(4)
    payload = f'{marker}"><x{marker}>'   # benign, unambiguous, no JS
    found = False

    checked = set()
    for candidate in _candidate_reflecting_urls(session, url, timeout):
        if candidate in checked:
            continue
        checked.add(candidate)
        try:
            r = session.get(candidate.replace("=test", "=" + payload, 1),
                            timeout=timeout)
        except requests.RequestException:
            continue

        if marker not in r.text:
            continue

        # If the marker itself is HTML-encoded, likely safe.
        encoded = f"{marker}&quot;&gt;&lt;x{marker}&gt;"
        if encoded in r.text:
            report.add(section, "OK", candidate, "payload was encoded")
            continue

        # Raw marker reflected with the tag intact.
        if f"{marker}\"><x{marker}>" in r.text or f'">{marker}' in r.text:
            found = True
            report.add(section, "WARNING", candidate,
                       "marker reflected without encoding — manual confirmation needed")

    if not found and not any(e["status"] == "WARNING" for e in report.data.get(section, [])):
        report.add(section, "OK", "no reflection detected",
                   f"checked {len(checked)} URL(s)")


def verify_open_redirect(report, session, url, timeout=8.0):
    """Check whether common redirect params accept external URLs."""
    section = "Open Redirect"
    canary = "https://" + secrets.token_hex(6) + ".example.org"
    found = False

    for param in ("next", "url", "redirect", "return", "returnTo",
                  "return_to", "continue", "dest", "destination", "r"):
        target = _mutate_query(url, param, canary)
        try:
            r = session.get(target, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        location = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and canary in location:
            found = True
            report.add(section, "WARNING", f"?{param}=",
                       f"redirects to attacker-controlled host ({r.status_code})")

    if not found:
        report.add(section, "OK", "no open redirect",
                   "no param accepted external host")


def verify_lfi(report, session, url, timeout=8.0):
    """Check common file parameters for path traversal using a harmless file."""
    section = "Local File Inclusion"
    # /etc/hostname is non-sensitive, ubiquitous, and small.
    payload = "../../../../../../etc/hostname"
    win_payload = "..\\..\\..\\..\\..\\windows\\win.ini"
    found = False

    def looks_like_linux_hostname(body):
        # A single-line hostname; not full of HTML tags.
        return ("<html" not in body.lower()
                and "<body" not in body.lower()
                and 0 < len(body) < 200
                and "\n" not in body.strip())

    def looks_like_winini(body):
        return "[fonts]" in body.lower() or "[extensions]" in body.lower()

    for param in ("file", "page", "path", "doc", "template", "view",
                  "include", "inc", "load", "read"):
        for pl, detector in ((payload, looks_like_linux_hostname),
                             (win_payload, looks_like_winini)):
            target = _mutate_query(url, param, pl)
            try:
                r = session.get(target, timeout=timeout)
            except requests.RequestException:
                continue
            if r.status_code == 200 and detector(r.text):
                found = True
                report.add(section, "WARNING", f"?{param}=",
                           "path traversal returned expected file content")

    if not found:
        report.add(section, "OK", "no LFI detected",
                   "checked common params with /etc/hostname and win.ini")


def verify_ssrf(report, session, url, timeout=8.0):
    """Check whether URL-accepting params fetch external resources.
    Uses a canary the caller controls — does NOT contact metadata endpoints
    (169.254.169.254) or internal services; that requires explicit scoping.
    """
    section = "SSRF (basic)"
    canary = "https://" + secrets.token_hex(6) + ".example.org"
    found = False
    for param in ("url", "uri", "link", "src", "image", "fetch",
                  "callback", "webhook", "target", "site"):
        target = _mutate_query(url, param, canary)
        try:
            r = session.get(target, timeout=timeout)
        except requests.RequestException:
            continue
        # A 500 caused by fetching an unresolvable canary is a hint, not proof.
        if r.status_code in (500, 502, 504):
            report.add(section, "INFO", f"?{param}=",
                       f"server errored on canary host (hint only, needs confirmation)")
            found = True

    if not found:
        report.add(section, "OK", "no SSRF hint",
                   "no URL param produced server-side fetch errors")
    else:
        report.add(section, "INFO", "next step",
                   "confirm SSRF with a scoped listener on a host you control")


def run_verification(report, session, url, timeout=8.0):
    verify_reflected_xss(report, session, url, timeout)
    verify_open_redirect(report, session, url, timeout)
    verify_lfi(report, session, url, timeout)
    verify_ssrf(report, session, url, timeout)