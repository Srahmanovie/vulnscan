# vulnscan

Non-intrusive website hardening checker with **opt-in** active scanning for authorized engagements.

> **Only run this against systems you own or have written authorization to test.**
> Active mode (`--active`) sends many additional requests that **will** appear in the target's access logs and may trip WAFs/IDS. Confirm scope, rate limits, and SOC contact in writing before running against a client system.

---

## What it does

### Passive mode (default — one request to the target)

| Check | Notes |
|---|---|
| Security headers | HSTS `max-age`/`includeSubDomains`, CSP `unsafe-inline`/`unsafe-eval`, COOP/CORP/COEP |
| Cookie flags | `Secure`, `HttpOnly`, `SameSite` — parsed from raw `Set-Cookie` |
| TLS certificate | Verified chain, expiry, protocol; falls back to unverified probe if the cert is bad |
| Info leakage | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` |
| CMS fingerprints | WordPress, Drupal, Joomla, Shopify |

### Active mode (`--active --i-have-authorization`)

| Check | Flag | Notes |
|---|---|---|
| `robots.txt` / `sitemap.xml` | `--active` | Reports `Disallow` lines |
| Exposed paths | `--active` | 11 common sensitive paths, soft-404-calibrated |
| Directory brute force | `--bruteforce` | Built-in wordlist or custom; per-host rate limit |
| Verification probes | `--verify` | XSS reflection, open redirect, LFI, SSRF hints — no exploitation |

### Deliberately **not** included

`vulnscan` does not exploit. For the exploitation phase use the tools built for it:

- SQLi → [sqlmap](https://sqlmap.org/)
- XSS → [dalfox](https://github.com/hahwul/dalfox), [XSStrike](https://github.com/s0md3v/XSStrike)
- SSRF → [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- LFI → [lfimap](https://github.com/hansmach1ne/LFImap)
- CVE checks → [nuclei](https://github.com/projectdiscovery/nuclei)
- General → Burp Suite, Metasploit

`vulnscan --verify` tells you *which URL and parameter* to aim those tools at.

---

## Install

```bash
git clone https://github.com/you/vulnscan.git
cd vulnscan
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Or as a script — just install the two dependencies and run `python vulnscan.py`:

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Passive scan (single request to the target)
vulnscan https://example.com

# JSON output
vulnscan https://example.com --json > report.json

# Active scan (robots, sitemap, common exposed paths)
vulnscan https://client.example --active --i-have-authorization

# Brute force + verification, polite rate limit
vulnscan https://client.example \
    --active --i-have-authorization \
    --bruteforce --verify \
    --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    --rate 0.5 --max-workers 4 \
    --json > report.json
```

### Wordlists

For real engagements, use [SecLists](https://github.com/danielmiessler/SecLists). Useful starting points:

```
Discovery/Web-Content/raft-small-directories.txt
Discovery/Web-Content/raft-medium-directories.txt
Discovery/Web-Content/common.txt
Discovery/Web-Content/backup-files-only.txt
```

The built-in wordlist (~70 entries) is a smoke test only — it is not a substitute.

---

## Output

Human-readable by default; `--json` emits:

```json
{
  "meta": {"target": "...", "mode": "active", "status": 200, ...},
  "sections": {
    "Security Headers": [
      {"status": "MISSING", "name": "Content-Security-Policy", "detail": "prevents XSS/injection"}
    ]
  }
}
```

Statuses: `OK`, `INFO`, `FOUND`, `EXPOSED`, `WARNING`, `MISSING`, `ERROR`.

---

## Before running against a client

Three things to confirm **in writing** with your client before using `--bruteforce` or `--verify`:

1. **Rate ceiling** — default is 1 request / 200 ms per host. Some clients require 1/sec or slower.
2. **WAF / SOC notification** — brute force trips WAFs. Confirm the SOC won't page on-call.
3. **Scope boundaries** — confirm outbound redirects to third-party hosts are out of scope, and that SSRF canaries must point at **your** infrastructure, not theirs.

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

---

## License

MIT — see [LICENSE](LICENSE).

## Responsible use

Running this tool against systems you do not own or have written authorization to test may be illegal in your jurisdiction. The author accepts no liability for misuse.
