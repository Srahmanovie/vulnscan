#!/usr/bin/env python3
"""
WordPress-specific scanning via WPScan.

Prerequisites:
  * WPScan installed and on PATH (Ruby >= 3.3)
  * A WPScan API token for vulnerability data (optional but recommended)

Usage from vulnscan.py:
  from wordpress import scan_wordpress
  scan_wordpress(report, target_url, api_token=os.getenv("WPSCAN_TOKEN"))
"""

import json
import os
import subprocess
import sys

# WPScan JSON structure reference:
# top-level keys: banner, target_url, effective_url, interesting_findings,
# version, main_theme, plugins, config_backups, vuln_api, ...
# https://wpscan.com/docs/api/v3/

DEFAULT_ENUMERATE = "vp,vt,u,cb,dbe"   # vulnerable plugins, vulnerable themes,
                                        # users, config backups, db exports
WPSCAN_TIMEOUT = 300                    # WPScan can be slow on large sites


def run_wpscan(target_url, api_token=None, enumerate_opts=None,
               detection_mode="mixed", plugins_detection="passive",
               timeout=WPSCAN_TIMEOUT):
    """
    Execute WPScan and return parsed JSON, or None on failure.

    Notes:
      * WPScan 4.0+ does NOT enumerate plugins by default.
      * --plugins-detection passive is quieter; switch to 'mixed' or
        'aggressive' only when you have explicit permission for noisy scans.
    """
    enum = enumerate_opts or DEFAULT_ENUMERATE

    cmd = [
        "wpscan",
        "--url", target_url,
        "--format", "json",
        "--enumerate", enum,
        "--detection-mode", detection_mode,
        "--plugins-detection", plugins_detection,
        "--no-update",                     # avoid surprise DB updates mid-scan
        "--disable-tls-checks",            # optional; remove if you want TLS strictness
    ]
    if api_token:
        cmd += ["--api-token", api_token]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print("wordpress: wpscan not found on PATH", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"wordpress: wpscan timed out after {timeout}s", file=sys.stderr)
        return None

    if proc.returncode not in (0, 5):   # WPScan uses 5 for 'no vulnerabilities found'
        print(f"wordpress: wpscan exited {proc.returncode}: {proc.stderr[:300]}",
              file=sys.stderr)
        return None

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        print(f"wordpress: could not parse wpscan JSON: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

def _add_core_findings(report, data):
    """Map WordPress core version + core vulnerabilities."""
    version = data.get("version") or {}
    number = version.get("number")
    status = version.get("status")          # latest / outdated / insecure
    vulns = version.get("vulnerabilities") or []

    if number:
        sev = "WARNING" if status in ("outdated", "insecure") else "OK"
        report.add("WordPress Core", sev, f"version {number}",
                   status or "unknown status")

    for v in vulns:
        title = v.get("title", "unnamed core vulnerability")
        cves = ", ".join(v.get("cve") or []) or "no CVE assigned"
        fixed = v.get("fixed_in") or "unknown fix version"
        report.add("WordPress Core", "WARNING", title,
                   f"{cves}; fixed in {fixed}")


def _add_plugin_findings(report, data):
    """Map plugin versions, outdated status, and plugin vulnerabilities."""
    plugins = data.get("plugins") or {}
    if not plugins:
        report.add("WordPress Plugins", "INFO", "plugins",
                   "none enumerated (WPScan 4.0+ requires --enumerate)")
        return

    for slug, info in plugins.items():
        version = (info.get("version") or {}).get("number") or "unknown"
        outdated = info.get("outdated")
        vulns = info.get("vulnerabilities") or []

        if vulns:
            for v in vulns:
                title = v.get("title", "unnamed plugin vulnerability")
                cves = ", ".join(v.get("cve") or []) or "no CVE"
                fixed = v.get("fixed_in") or "unknown"
                cvss = (v.get("cvss") or {}).get("score")
                detail = f"{cves}; fixed in {fixed}"
                if cvss is not None:
                    detail += f"; CVSS {cvss}"
                report.add("WordPress Plugins", "WARNING",
                           f"{slug} ({version}): {title}", detail)

        elif outdated:
            report.add("WordPress Plugins", "INFO", f"{slug} ({version})",
                       "outdated, no known CVE in current DB")
        else:
            report.add("WordPress Plugins", "OK", f"{slug} ({version})",
                       "no known vulnerabilities")


def _add_theme_findings(report, data):
    """Map main theme + installed themes and their vulnerabilities."""
    main = data.get("main_theme") or {}
    if main:
        _add_single_theme(report, main, label="main theme")

    # WPScan JSON exposes 'themes' in newer versions; keep it defensive.
    for slug, info in (data.get("themes") or {}).items():
        _add_single_theme(report, info, label=f"theme {slug}")


def _add_single_theme(report, info, label):
    slug = info.get("slug") or "unknown"
    version = (info.get("version") or {}).get("number") or "unknown"
    vulns = info.get("vulnerabilities") or []

    if vulns:
        for v in vulns:
            title = v.get("title", "unnamed theme vulnerability")
            cves = ", ".join(v.get("cve") or []) or "no CVE"
            report.add("WordPress Themes", "WARNING",
                       f"{label} {slug} ({version}): {title}", cves)
    else:
        report.add("WordPress Themes", "OK",
                   f"{label} {slug} ({version})", "no known vulnerabilities")


def _add_interesting_findings(report, data):
    """
    Map WPScan's 'interesting_findings' array.

    Typical entries: xmlrpc, readme, debug_log, robots.txt,
    config_backups, db_exports, headers, ...
    """
    findings = data.get("interesting_findings") or []
    if not findings:
        return

    for f in findings:
        ftype = f.get("type", "unknown")
        to_s = f.get("to_s") or f.get("url") or ""

        # Decide severity per finding type.
        severity = "INFO"
        if ftype in ("xmlrpc", "debug_log", "config_backup",
                     "db_export", "search_replace_db2"):
            severity = "WARNING"
        elif ftype == "readme":
            severity = "INFO"
        elif ftype == "robots.txt":
            severity = "INFO"

        entries = f.get("interesting_entries") or []
        detail = to_s
        if entries:
            detail += " | " + "; ".join(entries[:2])

        report.add("WordPress Findings", severity, ftype, detail[:200])


def _add_user_findings(report, data):
    """Map enumerated users (author IDs / usernames)."""
    users = data.get("users") or {}
    if not users:
        return

    for uid, info in users.items():
        username = info.get("username") or "unknown"
        report.add("WordPress Users", "INFO", f"user {uid}",
                   username)


def _add_config_backups(report, data):
    """Map config backup / DB export findings, if WPScan surfaced them."""
    for key, label in (("config_backups", "config backup"),
                       ("db_exports", "database export")):
        for path, info in (data.get(key) or {}).items():
            report.add("WordPress Findings", "WARNING", label, path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def scan_wordpress(report, target_url, api_token=None,
                   enumerate_opts=None, timeout=WPSCAN_TIMEOUT):
    """
    Run WPScan and populate `report`.

    Returns True if WPScan produced usable output, False otherwise.
    """
    data = run_wpscan(target_url, api_token=api_token,
                      enumerate_opts=enumerate_opts, timeout=timeout)
    if data is None:
        report.add("WordPress", "ERROR", "wpscan",
                   "could not run or parse WPScan output")
        return False

    report.set_meta("wpscan_version",
                    (data.get("banner") or {}).get("version"))
    report.set_meta("wpscan_api_plan",
                    (data.get("vuln_api") or {}).get("plan"))

    _add_core_findings(report, data)
    _add_plugin_findings(report, data)
    _add_theme_findings(report, data)
    _add_interesting_findings(report, data)
    _add_user_findings(report, data)
    _add_config_backups(report, data)

    return True