"""Minimal smoke tests — ensure the modules import and basic helpers work."""

import vulnscan
import activescan


def test_modules_import():
    assert vulnscan.TIMEOUT > 0
    assert activescan.DEFAULT_WORDLIST


def test_report_roundtrip():
    r = vulnscan.Report()
    r.add("Headers", "OK", "X-Frame-Options", "DENY")
    r.set_meta("target", "https://example.com")
    d = r.to_dict()
    assert d["meta"]["target"] == "https://example.com"
    assert d["sections"]["Headers"][0]["status"] == "OK"


def test_wordlist_loader_builtin():
    wl = activescan.load_wordlist(None)
    assert len(wl) > 50
    assert ".env" in wl


def test_query_mutation():
    url = "https://example.com/app?id=1&page=2"
    out = activescan._mutate_query(url, "next", "https://evil.test")
    assert "next=https%3A%2F%2Fevil.test" in out
    assert "id=1" in out
