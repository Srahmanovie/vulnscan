# Changelog

All notable changes to this project are documented here.

## [2.0.0] - 2026-04-18

### Added
- `activescan.py` module with directory brute forcing and non-destructive
  verification probes (XSS reflection, open redirect, LFI, SSRF hint).
- `--i-have-authorization` gate required for all active scanning.
- `--bruteforce`, `--wordlist`, `--verify`, `--max-workers`, `--rate` flags.
- `--json` output.
- Per-host rate limiting for active probes.
- Soft-404 calibration for exposed-path and brute-force checks.
- HSTS `max-age` / `includeSubDomains` analysis.
- CSP `unsafe-inline` / `unsafe-eval` / wildcard detection.
- `SameSite` cookie flag checking.
- `COOP`, `CORP`, `COEP` header checks.

### Fixed
- Cookie `HttpOnly` flag was reported inverted due to a falsy-value bug in
  `has_nonstandard_attr`.
- SSL "EXPIRED" branch was unreachable because `create_default_context()`
  raises before `getpeercert()` on an expired certificate.
- Exposed-path and robots probes used path-relative URL joining; now root-relative.
- SSL check hardcoded port 443; now uses the port from the target URL.
- Silent `except: pass` in path probes; errors are now reported.
- Deprecated `datetime.utcnow()` replaced with timezone-aware `now(timezone.utc)`.

### Changed
- Tool no longer claims "passive only". Active probes are gated behind
  `--active --i-have-authorization` and the help text is explicit about logging.

## [1.0.0] - initial

- Header, cookie, SSL, info-leakage, exposed-path, robots and CMS-fingerprint checks.
