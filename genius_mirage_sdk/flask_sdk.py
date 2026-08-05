"""
genius_mirage_sdk/flask_sdk.py
================================
Flask middleware for Genius Mirage client sites (v5.1 — combined process mode).

Usage:
    from genius_mirage_sdk.flask_sdk import init_genius_mirage
    app = Flask(__name__)
    init_genius_mirage(
        app,
        site_id='your-site-id',
        api_url='https://your-platform.com',
        api_token='your-auth-token',
    )

How it works
------------
On every incoming request (except static assets), this middleware sends the
FULL request context — method, path, query string, body, headers, user agent,
client IP — to Genius Mirage's `/api/swap/process/` endpoint in ONE call.

Genius Mirage:
  1. Runs the three-tier evaluation engine on this request (if the session
     isn't already flagged).
  2. If the session is (or becomes) flagged, generates a decoy response and
     returns it immediately.
  3. Otherwise returns {"backend_type": "real"} and your Flask app continues
     normally.

This means SQL injection in POST bodies, header anomalies, command injection
in form fields — everything — is visible to the evaluator, not just the URL.

Fail-open guarantee
--------------------
If the platform is unreachable or times out, this middleware does nothing —
your site continues working exactly as normal. Real users are never impacted.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

logger = logging.getLogger('genius_mirage_sdk')

_BYPASS_PREFIXES = ('/static/', '/public/', '/favicon.ico', '/robots.txt', '/.well-known/')

PROCESS_TIMEOUT_S = 4.0


def init_genius_mirage(app, site_id: str, api_url: str, api_token: str):
    """Register the Genius Mirage before_request hook on a Flask app."""
    try:
        import requests as _http
    except ImportError:
        logger.warning('[GeniusMirage SDK] "requests" not installed — SDK disabled.')
        return

    base = api_url.rstrip('/')

    def _session_id(request) -> str:
        cookie_name = f'_gm_sid_{site_id[:8]}'
        sid = request.cookies.get(cookie_name)
        if sid:
            return sid
        ip = (request.headers.get('X-Forwarded-For', '') or
              request.remote_addr or '').split(',')[0].strip()
        ua = request.headers.get('User-Agent', '')[:80]
        return 'sdk-' + hashlib.md5(f'{ip}:{ua}:{site_id}'.encode()).hexdigest()[:24]

    def _client_ip(request) -> str:
        return (request.headers.get('X-Forwarded-For', '') or
                request.remote_addr or '0.0.0.0').split(',')[0].strip()

    def _process(session_id: str, request) -> Optional[dict]:
        try:
            raw_body = request.get_data(as_text=True) or ''
            r = _http.post(
                f'{base}/api/swap/process/',
                json={
                    'session_id':   session_id,
                    'site_id':      site_id,
                    'path':         request.path,
                    'method':       request.method,
                    'query_string': request.query_string.decode('utf-8', errors='replace'),
                    'body':         raw_body[:5000],
                    'user_agent':   request.headers.get('User-Agent', ''),
                    'headers':      {k: v for k, v in request.headers.items()
                                     if k.lower() not in ('cookie', 'authorization')},
                    'ip_address':   _client_ip(request),
                },
                headers={'Authorization': f'Token {api_token}'},
                timeout=PROCESS_TIMEOUT_S,
            )
            if r.status_code == 200:
                return r.json()
            logger.debug('[GeniusMirage SDK Flask] process returned %s', r.status_code)
        except Exception as exc:
            logger.debug('[GeniusMirage SDK Flask] process call failed (fail-open): %s', exc)
        return None

    @app.before_request
    def genius_mirage_intercept():
        from flask import request, make_response

        for prefix in _BYPASS_PREFIXES:
            if request.path.startswith(prefix):
                return None

        session_id = _session_id(request)
        result = _process(session_id, request)

        if not result:
            return None  # Platform unreachable — fail open

        if result.get('backend_type') != 'deceptive':
            return None  # Clean — let Flask handle the request as normal

        delay_ms = min(result.get('response_delay_ms', 0), 2000)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        resp = make_response(
            result.get('body', ''),
            int(result.get('status_code', 200)),
        )
        resp.mimetype = result.get('content_type', 'application/json')
        for k, v in (result.get('headers') or {}).items():
            if k.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                resp.headers[k] = v

        cookie_name = f'_gm_sid_{site_id[:8]}'
        if not request.cookies.get(cookie_name):
            resp.set_cookie(cookie_name, session_id, max_age=7200, httponly=True, samesite='Lax')

        return resp

    @app.after_request
    def genius_mirage_set_cookie(response):
        from flask import request
        cookie_name = f'_gm_sid_{site_id[:8]}'
        if not request.cookies.get(cookie_name):
            sid = _session_id(request)
            response.set_cookie(cookie_name, sid, max_age=7200, httponly=True, samesite='Lax')
        return response
