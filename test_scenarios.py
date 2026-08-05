#!/usr/bin/env python3
"""
test_scenarios.py
==================
Automated, repeatable test suite for exercising Genius Mirage's three-tier
evaluator against this test site — no browser, no dashboard-watching
required.

Why this exists
----------------
The README's Step 6 walks through each vulnerability class manually (visit
a URL, watch the dashboard). That's the right way to *see* the system work
end to end, but it doesn't scale to regression testing: there's no
repeatable pass/fail signal, and — critically — it only covers attack
traffic. It never checks the other half of the story: does a real customer
doing something slightly unusual (a legitimate API integration, a CDN in
front of the site, a QA bot, a customer who just opens an invoice link)
get left alone?

This script calls Genius Mirage's `/api/swap/process/` endpoint directly —
the exact same call the SDK (genius_mirage_sdk/flask_sdk.py) makes on every
request — so it exercises the real evaluator over the real network path,
but gets back a structured JSON verdict (`backend_type`, `tier`, `score`)
instead of a decoy page a human has to eyeball. That verdict is ground
truth, which is what makes this automatable.

Three scenario groups:
  1. TIER 1  — deterministic attacks. Every one of these must flag on the
               very first request.
  2. TIER 2  — behavioural accumulation (brute force, IDOR enumeration).
               The first request or two must NOT flag; the pattern as a
               whole must.
  3. FALSE POSITIVE REGRESSION — legitimate-but-unusual traffic that
     previously would have scored high enough to flag or burn a Tier 3 AI
     review: a plain API client, a multi-hop CDN chain, a headless QA bot,
     ordinary dynamic product/invoice URLs. These must NOT flag.

Usage
-----
    export GM_SITE_ID='site-...'
    export GM_API_URL='http://127.0.0.1:8000'
    export GM_API_TOKEN='...'
    python test_scenarios.py                  # run everything
    python test_scenarios.py --category fp     # just the false-positive suite
    python test_scenarios.py --category tier1
    python test_scenarios.py --category tier2

Exit code is non-zero if any hard expectation fails, so this is safe to
wire into CI.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

try:
    import config as _site_config
except Exception:
    _site_config = None


# ═══════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════

def _cfg(env_name: str, attr_name: str, default: str = '') -> str:
    val = os.environ.get(env_name, '')
    if val:
        return val
    if _site_config is not None:
        return getattr(_site_config, attr_name, default) or default
    return default


API_URL = _cfg('GM_API_URL', 'GENIUS_MIRAGE_API_URL', 'http://127.0.0.1:8000').rstrip('/')
SITE_ID = _cfg('GM_SITE_ID', 'GENIUS_MIRAGE_SITE_ID', '')
API_TOKEN = _cfg('GM_API_TOKEN', 'GENIUS_MIRAGE_API_TOKEN', '')

BROWSER_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
BROWSER_HEADERS = {'Accept': 'text/html,application/xhtml+xml',
                    'Accept-Encoding': 'gzip, deflate, br'}


# ═══════════════════════════════════════════════════════════════════════
# Scenario model
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class Step:
    method: str
    path: str
    query_string: str = ''
    body: str = ''
    user_agent: str = BROWSER_UA
    headers: Dict[str, str] = field(default_factory=lambda: dict(BROWSER_HEADERS))
    ip_address: str = '198.51.100.20'
    expect_flagged: Optional[bool] = None   # None = observe only, don't assert
    note: str = ''


@dataclass
class Scenario:
    name: str
    category: str  # 'tier1' | 'tier2' | 'fp' | 'tier3'
    steps: List[Step]


def _call(session_id: str, step: Step) -> dict:
    payload = {
        'session_id': session_id,
        'site_id': SITE_ID,
        'path': step.path,
        'method': step.method,
        'query_string': step.query_string,
        'body': step.body,
        'user_agent': step.user_agent,
        'headers': step.headers,
        'ip_address': step.ip_address,
    }
    resp = requests.post(
        f'{API_URL}/api/swap/process/',
        json=payload,
        headers={'Authorization': f'Token {API_TOKEN}'},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════
# Scenario definitions
# ═══════════════════════════════════════════════════════════════════════

SCENARIOS: List[Scenario] = [

    # ── TIER 1: deterministic, must flag on request #1 ──────────────────
    Scenario('SQLi UNION SELECT on /product/<id>', 'tier1', [
        Step('GET', '/product/1 UNION SELECT id,name,category,price,description,sku,in_stock FROM products',
             expect_flagged=True, note='Definitive SQLi payload'),
    ]),
    Scenario("SQLi ' OR '1'='1 on /search", 'tier1', [
        Step('GET', '/search', query_string="q=' OR '1'='1",
             expect_flagged=True, note='Definitive SQLi payload'),
    ]),
    Scenario('Path traversal to /etc/passwd', 'tier1', [
        Step('GET', '/download', query_string='file=../../etc/passwd',
             expect_flagged=True, note='Sensitive OS file traversal'),
    ]),
    Scenario('Command injection in order tracker', 'tier1', [
        Step('POST', '/support/tools/track', body='order_ref=ORD-100231; whoami',
             expect_flagged=True, note='Shell metacharacter + command'),
    ]),
    Scenario('SSTI in product preview', 'tier1', [
        Step('POST', '/support/tools/preview', body='product_name={{config}}',
             expect_flagged=True, note='Jinja2 SSTI payload'),
    ]),
    Scenario('Honeypot file access (/.env)', 'tier1', [
        Step('GET', '/.env', expect_flagged=True, note='Honey path'),
    ]),
    Scenario('Known scanner tool UA (sqlmap)', 'tier1', [
        Step('GET', '/', user_agent='sqlmap/1.7.2#stable', headers={},
             expect_flagged=True, note='Attack-tool UA, Tier 1 absolute match'),
    ]),

    # ── TIER 2: accumulation — early requests clean, pattern flags ──────
    Scenario('Credential brute force on /login', 'tier2', [
        Step('POST', '/login', body='username=admin&password=wrong1',
             expect_flagged=False, note='1st attempt — should look like a typo'),
        Step('POST', '/login', body='username=admin&password=wrong2',
             expect_flagged=False, note='2nd attempt — still ambiguous'),
        Step('POST', '/login', body='username=admin&password=wrong3'),
        Step('POST', '/login', body='username=admin&password=wrong4'),
        Step('POST', '/login', body='username=admin&password=wrong5'),
        Step('POST', '/login', body='username=admin&password=wrong6',
             expect_flagged=True, note='Sustained rapid failed logins'),
    ]),
    Scenario('Sequential invoice ID enumeration (IDOR)', 'tier2', [
        Step('GET', '/account/invoice/1', expect_flagged=False, note='Own invoice'),
        Step('GET', '/account/invoice/2', expect_flagged=False, note='Own invoice'),
        Step('GET', '/account/invoice/3', expect_flagged=False, note='Own invoice'),
        Step('GET', '/account/invoice/4', note="Not the caller's invoice"),
        Step('GET', '/account/invoice/5'),
        Step('GET', '/account/invoice/6',
             expect_flagged=True, note='6 sequential IDs — enumeration pattern'),
    ]),
    Scenario('Recon: unlinked admin portal + CMS probing', 'tier2', [
        Step('GET', '/admin-portal', expect_flagged=False,
             note='Single recon hit alone should not hard-flag (signal-diversity gate)'),
        Step('GET', '/wp-admin', headers={}),
        Step('GET', '/wp-login.php', headers={}),
        Step('GET', '/phpmyadmin', headers={},
             note='Stacked recon probes across a short session'),
    ]),

    # ── FALSE POSITIVE REGRESSION — must stay unflagged ──────────────────
    Scenario('[FP] Legit server-to-server API client', 'fp', [
        Step('GET', '/product/2', user_agent='python-requests/2.31.0', headers={},
             expect_flagged=False,
             note='No Accept/Accept-Encoding headers — used to double-count'),
    ]),
    Scenario('[FP] CDN / WAF / load-balancer forwarding chain', 'fp', [
        Step('GET', '/', headers={
                 **BROWSER_HEADERS,
                 'X-Forwarded-For': '203.0.113.5, 198.51.100.2, 192.0.2.9, 10.0.0.1',
             },
             expect_flagged=False,
             note='4-hop chain — normal enterprise topology, not spoofing'),
    ]),
    Scenario('[FP] Headless QA / uptime-monitor bot', 'fp', [
        Step('GET', '/', user_agent='Mozilla/5.0 HeadlessChrome/120.0.0.0 Playwright',
             expect_flagged=False,
             note='Legit automated browser testing/monitoring'),
    ]),
    Scenario('[FP] Ordinary single product page view', 'fp', [
        Step('GET', '/product/5', expect_flagged=False,
             note='Baseline: normal browsing must never flag'),
    ]),
    Scenario('[FP] Single invoice view (not enumeration)', 'fp', [
        Step('GET', '/account/invoice/2', expect_flagged=False,
             note='One invoice view, contrast with the IDOR scenario above'),
    ]),
    Scenario('[FP] curl health-check style request', 'fp', [
        Step('GET', '/', user_agent='curl/8.4.0', headers={},
             expect_flagged=False,
             note='Bare curl request — common for uptime checks/webhooks'),
    ]),

    # ── TIER 3 / borderline — observe, don't hard-assert ─────────────────
    Scenario('[Borderline] Ambiguous search phrase', 'tier3', [
        Step('GET', '/search', query_string='q=drop leaf table',
             note='Plausible real customer query that contains a SQL keyword'),
    ]),
]


# ═══════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════

def run(category_filter: Optional[str], delay: float) -> bool:
    if not SITE_ID or not API_TOKEN:
        print("Missing GM_SITE_ID / GM_API_TOKEN. Set them as environment "
              "variables or fill in config.py (see README.md Step 3).")
        return False

    scenarios = [s for s in SCENARIOS if not category_filter or s.category == category_filter]
    if not scenarios:
        print(f"No scenarios match category '{category_filter}'.")
        return False

    all_passed = True
    counts = {'pass': 0, 'fail': 0, 'observe': 0}

    for scenario in scenarios:
        print(f"\n=== [{scenario.category.upper()}] {scenario.name} ===")
        session_id = f"test-{uuid.uuid4().hex[:16]}"

        for i, step in enumerate(scenario.steps, start=1):
            try:
                result = _call(session_id, step)
            except requests.RequestException as exc:
                print(f"  step {i}: ERROR — request failed: {exc}")
                all_passed = False
                counts['fail'] += 1
                continue

            flagged = result.get('backend_type') == 'deceptive'
            eval_info = result.get('eval', {}) or {}
            tier = eval_info.get('tier')
            score = eval_info.get('score')
            desc = f"{step.method} {step.path}"
            if step.query_string:
                desc += f"?{step.query_string}"

            if step.expect_flagged is None:
                counts['observe'] += 1
                tag = 'OBSERVE'
            elif flagged == step.expect_flagged:
                counts['pass'] += 1
                tag = 'PASS'
            else:
                counts['fail'] += 1
                all_passed = False
                tag = 'FAIL'

            note = f" — {step.note}" if step.note else ''
            expect_str = ('any' if step.expect_flagged is None
                          else ('flagged' if step.expect_flagged else 'clean'))
            print(f"  [{tag:^7}] step {i}: {desc}{note}\n"
                  f"            expected={expect_str:8s} got={'flagged' if flagged else 'clean':8s} "
                  f"tier={tier} score={score}")

            if delay:
                time.sleep(delay)

    print(f"\n{'='*70}\nSummary: {counts['pass']} passed, {counts['fail']} failed, "
          f"{counts['observe']} observed (no hard expectation)\n{'='*70}")
    return all_passed


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--category', choices=['tier1', 'tier2', 'fp', 'tier3'],
                         help='Only run scenarios in this category')
    parser.add_argument('--delay', type=float, default=0.1,
                         help='Seconds to sleep between steps (default 0.1)')
    args = parser.parse_args()

    ok = run(args.category, args.delay)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
