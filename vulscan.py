#!/usr/bin/env python3
"""
Non-intrusive website hardening checker with opt-in active scanning.

For use ONLY on sites you own or are authorized to test.

Default ("passive") mode inspects the initial HTTP response and the TLS
certificate. It sends no extra requests beyond the single GET to the target.

Pass --active plus --i-have-authorization to unlock:
  * robots.txt / sitemap.xml / common exposed-path probes
  * --bruteforce  → directory/file brute forcing (wordlist-driven)
  * --verify      → non-destructive verification of XSS reflection,
                    open redirect, LFI, and basic SSRF hints

Pass --wordpress to additionally run WPScan when WordPress is detected
(requires wpscan on PATH; WPSCAN_TOKEN env var recommended).

Active mode is noisy: the target server WILL log every request.
"""

import argparse
import datetime
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


TIMEOUT = 8.0
USER_AGENT = "Mozilla/5.0 (compatible; vulnscan/2.0; hardening-check)"
PROBE_INTERVAL = 0.20
MAX_WORKERS = 4
HSTS_MIN_AGE = 15552000


# ---------- global throttle for active probes ----------

_throttle_lock = threading.Lock()
_throttle_last = 0.0


def _throttle(interval):
    global _throttle_last
    with _throttle_lock:
        wait = _throttle_last + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _throttle_last = time.monotonic()


# ---------- report ----------

class Report:
    def __init__(self):
        self.data = {}
        self.meta = {}

    def add(self, section, status, name, detail=""):
        self.data.setdefault(section, []).append(
            {"status": status, "name": name, "detail": detail}
        )

    def set_meta(self, key, value):
        self.meta[key] = value

    def summary(self):
        counts = {}
        for entries in self.data.values():
            for e in entries:
                counts[e["status"]] = counts.get(e["status"], 0) + 1
        return counts

    def print_human(self):
        for section, entries in self.data.items():
            print(f"\n--- {section} ---")
            for e in entries:
                line = f"{e['status']:9} {e['name']}"
                if e["detail"]:
                    line += f"  ({e['detail']})"
                print(line)
        print("\n" + "=" * 60)
        counts = self.summary()
        order = ["OK", "INFO", "FOUND", "EXPOSED", "WARNING", "MISSING", "ERROR"]
        parts = [f"{s}: {counts[s]}" for s in order if s in counts]
        print("Summary: " + ", ".join(parts))
        print("Use only on sites you own or are authorized to test.")

    def to_dict(self):
        return {"meta": self.meta, "sections": self.data}


# ---------- passive checks ----------

def check_headers(report, r):
    section = "Security Headers"

    hsts = r.headers.get("Strict-Transport-Security")
    if not hsts:
        report.add(section, "MISSING", "Strict-Transport-Security", "enforces HTTPS")
    else:
        issues = []
        if "includesubdomains" not in hsts.lower():
            issues.append("no includeSubDomains")
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not m:
            issues.append("missing max-age")
        elif int(m.group(1)) < HSTS_MIN_AGE:
            issues.append(f"max-age={m.group(1)} < {HSTS_MIN_AGE}s")
        report.add(section, "OK" if not issues else "WARNING",
                   "Strict-Transport-Security",
                   hsts + ("; " + ", ".join(issues) if issues else ""))

    csp = r.headers.get("Content-Security-Policy")
    if not csp:
        report.add(section, "MISSING", "Content-Security-Policy", "prevents XSS/injection")
    else:
        issues = []
        low = csp.lower()
        if "unsafe-inline" in low:
            issues.append("unsafe-inline")
        if "unsafe-eval" in low:
            issues.append("unsafe-eval")
        if re.search(r"default-src[^;]*\*", low):
            issues.append("default-src wildcard")
        report.add(section, "OK" if not issues else "WARNING",
                   "Content-Security-Policy",
                   ", ".join(issues) if issues else "basic policy present")

    simple = [
        ("X-Frame-Options", "prevents clickjacking"),
        ("X-Content-Type-Options", "prevents MIME sniffing"),
        ("Referrer-Policy", "controls referrer leakage"),
        ("Permissions-Policy", "restricts browser features"),
        ("Cross-Origin-Opener-Policy", "isolates browsing context"),
        ("Cross-Origin-Resource-Policy", "restricts resource loading"),
        ("Cross-Origin-Embedder-Policy", "prevents cross-origin leaks"),
    ]
    for h, desc in simple:
        if h in r.headers:
            report.add(section, "OK", h, r.headers[h][:100])
        else:
            report.add(section, "MISSING", h, desc)


def check_info_leakage(report, r):
    section = "Info Leakage"
    found = False
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if h in r.headers:
            found = True
            report.add(section, "EXPOSED", h, r.headers[h][:100])
    if not found:
        report.add(section, "OK", "version/stack headers", "none exposed")


def check_cookies(report, r):
    section = "Cookie Security"
    raw_cookies = []
    for resp in [*r.history, r]:
        try:
            raw_cookies.extend(resp.raw.headers.getlist("Set-Cookie"))
        except AttributeError:
            pass

    if not raw_cookies:
        report.add(section, "OK", "cookies", "none set on initial response")
        return

    seen = set()
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip() or "<unnamed>"
        if name in seen:
            continue
        seen.add(name)

        parts = [p.strip().lower() for p in raw.split(";")]
        flags = parts[1:]
        issues = []
        if "secure" not in flags:
            issues.append("missing Secure")
        if "httponly" not in flags:
            issues.append("missing HttpOnly")

        samesite = next((f for f in flags if f.startswith("samesite")), None)
        if not samesite:
            issues.append("missing SameSite")
        elif samesite in ("samesite=none", "samesite") and "secure" not in flags:
            issues.append("SameSite=None requires Secure")

        report.add(section, "OK" if not issues else "WARNING",
                   f"cookie '{name}'",
                   ", ".join(issues) if issues else "Secure, HttpOnly, SameSite set")


def check_ssl(report, hostname, port):
    section = "SSL/TLS Certificate"
    now = datetime.datetime.now(datetime.timezone.utc)
    proto = None
    nb = na = None
    verified = False
    verify_error = None

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version()
                nb, na = _cert_dates(ssock)
                verified = True
    except ssl.SSLCertVerificationError as e:
        verify_error = getattr(e, "verify_message", str(e))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        report.add(section, "ERROR", "connection", str(e))
        return
    except Exception as e:
        verify_error = str(e)

    if not verified:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    proto = ssock.version()
                    nb, na = _cert_dates(ssock)
        except Exception as e:
            report.add(section, "ERROR", "unverified probe", str(e))

    if verified:
        report.add(section, "OK", "certificate verification",
                   "chain valid, hostname matches")
    elif verify_error:
        report.add(section, "ERROR", "certificate verification", verify_error)

    if proto:
        report.add(section, "INFO", "protocol", proto)
        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            report.add(section, "WARNING", "protocol", f"outdated: {proto}")

    if na:
        if nb:
            report.add(section, "INFO", "valid from", nb.date().isoformat())
        days_left = (na - now).days
        if now > na:
            report.add(section, "WARNING", "expiry",
                       f"EXPIRED on {na.date().isoformat()}")
        elif nb and now < nb:
            report.add(section, "WARNING", "expiry",
                       f"not yet valid (starts {nb.date().isoformat()})")
        elif days_left < 30:
            report.add(section, "WARNING", "expiry",
                       f"expires in {days_left} days ({na.date().isoformat()})")
        else:
            report.add(section, "OK", "expiry",
                       f"valid for {days_left} days ({na.date().isoformat()})")
    elif verified and not HAVE_CRYPTOGRAPHY:
        report.add(section, "INFO", "expiry",
                   "install 'cryptography' for detailed dates")


def _cert_dates(ssock):
    if HAVE_CRYPTOGRAPHY:
        der = ssock.getpeercert(binary_form=True)
        if not der:
            return None, None
        cert = x509.load_der_x509_certificate(der, default_backend())
        nb = (cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc")
              else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc))
        na = (cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc")
              else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc))
        return nb, na

    info = ssock.getpeercert()
    if not info:
        return None, None
    return _parse_asn1(info.get("notBefore")), _parse_asn1(info.get("notAfter"))


def _parse_asn1(s):
    if not s:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def check_software_hints(report, r):
    """
    Returns the set of detected CMS names, e.g. {"WordPress"}.
    The caller uses this to decide whether to run CMS-specific scanners.
    """
    section = "Outdated Software Hints"
    hints = []

    if "Server" in r.headers:
        hints.append(("INFO", "Server header", r.headers["Server"][:100]))
    if "X-Powered-By" in r.headers:
        hints.append(("INFO", "X-Powered-By header", r.headers["X-Powered-By"][:100]))

    text_lower = r.text.lower()[:50000]
    signatures = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "shopify": "Shopify",
    }
    seen = set()
    for sig, name in signatures.items():
        if sig in text_lower and name not in seen:
            seen.add(name)
            hints.append(("INFO", "CMS signature", f"{name} (matched '{sig}')"))

    for status, name, detail in hints:
        report.add(section, status, name, detail)

    if not hints:
        report.add(section, "OK", "fingerprints", "none found")
    else:
        report.add(section, "INFO", "next step",
                   "cross-check reported versions against vendor advisories")

    return seen


# ---------- active checks (require --active + --i-have-authorization) ----------

def check_robots_sitemap(report, session, base_url):
    section = "robots.txt / sitemap.xml"
    for path in ("/robots.txt", "/sitemap.xml"):
        _throttle(PROBE_INTERVAL)
        try:
            resp = session.get(urljoin(base_url, path), timeout=TIMEOUT)
        except requests.RequestException as e:
            report.add(section, "ERROR", path, str(e))
            continue
        if resp.status_code == 200:
            report.add(section, "FOUND", path, f"{len(resp.text)} bytes")
            if path == "/robots.txt":
                disallowed = [ln.strip() for ln in resp.text.splitlines()
                              if ln.lower().startswith("disallow")]
                for d in disallowed[:10]:
                    report.add(section, "INFO", "  " + d)
                if len(disallowed) > 10:
                    report.add(section, "INFO",
                               f"  ...and {len(disallowed) - 10} more")
        else:
            report.add(section, "MISSING", path, str(resp.status_code))


def check_exposed_paths(report, session, base_url):
    section = "Exposed Files/Paths"
    baseline_path = "/" + secrets.token_hex(8)
    try:
        baseline = session.get(urljoin(base_url, baseline_path),
                               timeout=TIMEOUT, allow_redirects=False)
        baseline_status = baseline.status_code
        baseline_len = len(baseline.content)
    except requests.RequestException as e:
        report.add(section, "ERROR", "baseline request", str(e))
        return

    tolerance = max(100, int(baseline_len * 0.10))
    paths = [
        "/.git/config", "/.env", "/wp-config.php.bak",
        "/admin", "/backup.zip", "/.DS_Store",
        "/phpinfo.php", "/server-status", "/.htaccess",
        "/config.php.bak", "/.svn/entries",
    ]
    errors = []

    def probe(path):
        _throttle(PROBE_INTERVAL)
        try:
            resp = session.get(urljoin(base_url, path),
                               timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            errors.append((path, str(e)))
            return None
        same_status = resp.status_code == baseline_status
        same_len = abs(len(resp.content) - baseline_len) <= tolerance
        if same_status and (resp.status_code >= 400 or same_len):
            return None
        return (path, resp.status_code, len(resp.content))

    hits = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(probe, p) for p in paths]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                hits.append(result)

    for path, status, length in sorted(hits, key=lambda x: x[0]):
        if status == 200:
            report.add(section, "FOUND", path, f"200 OK, {length} bytes")
        elif status in (301, 302, 303, 307, 308):
            report.add(section, "INFO", path, f"redirect ({status})")
        elif status in (401, 403):
            report.add(section, "INFO", path, f"access denied ({status})")
        else:
            report.add(section, "INFO", path, f"unusual response ({status})")

    if not hits:
        report.add(section, "OK", "exposed paths",
                   "no common sensitive paths returned 200/redirect")
    if errors:
        report.add(section, "ERROR", "some probes failed",
                   f"{len(errors)} error(s); e.g. {errors[0][0]}: {errors[0][1][:80]}")


# ---------- orchestrator ----------

def scan(target, active=False, authorized=False, timeout=TIMEOUT,
         bruteforce=False, wordlist=None, verify=False,
         wordpress=False, max_workers=6, rate=0.20):
    global TIMEOUT
    TIMEOUT = timeout

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    if not parsed.hostname:
        print(f"Invalid URL: {target}", file=sys.stderr)
        sys.exit(2)

    if active and not authorized:
        print("Refusing active mode: --active requires --i-have-authorization",
              file=sys.stderr)
        sys.exit(2)

    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    base_url = f"{scheme}://{parsed.netloc}"

    report = Report()
    report.set_meta("target", target)
    report.set_meta("mode", "active" if active else "passive")
    report.set_meta("started",
                    datetime.datetime.now(datetime.timezone.utc).isoformat())

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    try:
        r = session.get(target, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"Could not reach {target}: {e}", file=sys.stderr)
        sys.exit(1)

    report.set_meta("final_url", r.url)
    report.set_meta("status", r.status_code)
    report.set_meta("elapsed", f"{r.elapsed.total_seconds():.2f}s")

    check_headers(report, r)
    check_info_leakage(report, r)
    check_cookies(report, r)
    if scheme == "https":
        check_ssl(report, hostname, port)
    cms_detected = check_software_hints(report, r)
    report.set_meta("cms_detected", sorted(cms_detected))

    if active:
        check_robots_sitemap(report, session, base_url)
        check_exposed_paths(report, session, base_url)

        try:
            import activescan
        except ImportError:
            print("activescan.py not found — required for --bruteforce / --verify",
                  file=sys.stderr)
            sys.exit(2)

        if bruteforce:
            wl = activescan.load_wordlist(wordlist)
            activescan.brute_force(report, session, base_url, wl, timeout,
                                   max_workers=max_workers,
                                   rate_interval=rate)
        if verify:
            activescan.run_verification(report, session, target, timeout)

    if wordpress:
        if "WordPress" not in cms_detected:
            report.add("WordPress", "INFO", "skipped",
                       "WordPress not detected on this target")
        else:
            try:
                from wordpress import scan_wordpress
                scan_wordpress(report, target,
                               api_token=os.getenv("WPSCAN_TOKEN"))
            except ImportError:
                report.add("WordPress", "ERROR", "wpscan module",
                           "wordpress.py not found in the same directory")
            except Exception as e:
                report.add("WordPress", "ERROR", "wpscan", str(e)[:120])

    report.set_meta("finished",
                    datetime.datetime.now(datetime.timezone.utc).isoformat())
    return report


def main():
    ap = argparse.ArgumentParser(
        description=("Non-intrusive website hardening checker. "
                     "Use only on sites you own or are authorized to test."),
    )
    ap.add_argument("url", help="target URL")
    ap.add_argument("--active", action="store_true",
                    help="enable out-of-band probes (robots.txt, sitemap.xml, "
                         "sensitive paths). Requires --i-have-authorization.")
    ap.add_argument("--i-have-authorization", action="store_true",
                    help="required for all active probes; confirms you have "
                         "written permission to test the target")
    ap.add_argument("--bruteforce", action="store_true",
                    help="directory/file brute forcing (requires --active)")
    ap.add_argument("--wordlist", metavar="FILE",
                    help="custom wordlist (default: built-in)")
    ap.add_argument("--verify", action="store_true",
                    help="non-destructive verification probes "
                         "(XSS reflection, open redirect, LFI, SSRF hint)")
    ap.add_argument("--wordpress", action="store_true",
                    help="run WPScan when WordPress is detected "
                         "(requires wpscan on PATH; WPSCAN_TOKEN env recommended)")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of human-readable text")
    ap.add_argument("--timeout", type=float, default=TIMEOUT,
                    help="per-request timeout in seconds (default: %(default)s)")
    ap.add_argument("--max-workers", type=int, default=6,
                    help="concurrency cap for active probes (default: %(default)s)")
    ap.add_argument("--rate", type=float, default=0.20,
                    help="min seconds between requests per host "
                         "(default: %(default)s)")
    args = ap.parse_args()

    report = scan(
        args.url,
        active=args.active,
        authorized=args.i_have_authorization,
        timeout=args.timeout,
        bruteforce=args.bruteforce,
        wordlist=args.wordlist,
        verify=args.verify,
        wordpress=args.wordpress,
        max_workers=args.max_workers,
        rate=args.rate,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    print(f"Scanning {report.meta['target']}")
    print(f"Mode:     {report.meta['mode']}")
    print(f"Status:   {report.meta['status']}  |  "
          f"Response time: {report.meta['elapsed']}")
    if report.meta.get("cms_detected"):
        print(f"CMS:      {', '.join(report.meta['cms_detected'])}")
    if args.active:
        print("Note:     active probes enabled; the server will log these requests.")
    print("=" * 60)
    report.print_human()


if __name__ == "__main__":
    main()