# Northbridge Office Supplies — Genius Mirage Test Site

A small, ordinary-looking office-supplies storefront, built specifically as a
**local test target** for exercising Genius Mirage's three-tier evaluation
and backend-swap functionality end to end.

This is not a CTF box dressed up to look vulnerable — it's a normal small
business site (catalog, login, account/invoices, contact form, a couple of
self-service tools) implemented the way an under-resourced dev shop might
actually write it, with real, unintentional-looking security gaps baked into
ordinary features. Genius Mirage doesn't know this is a test site, and the
site doesn't know it's "supposed" to be caught — that's the point.

## What's deliberately vulnerable (and why it's realistic)

| Route | Vulnerability | Why a real site might have this |
|---|---|---|
| `/product/<id>` | SQL injection | Numeric ID lookups often get written as raw string-formatted queries |
| `/search?q=` | SQL injection | Same pattern in a `LIKE` clause for the search box |
| `/login` | Credential brute force | Plaintext comparison, no rate limit — common in early-stage apps |
| `/account/invoice/<id>` | IDOR | Sequential IDs, no ownership check on a "view my invoice" route |
| `/support/tools/track` | Command injection | A "delivery status" feature wrapping a shell call |
| `/support/tools/preview` | SSTI | A "preview message" feature naively rendering user input as a template |
| `/download?file=` | Path traversal | A "download the brochure" feature with naive path joining |
| `/admin-portal` | Recon target | Unlinked, only excluded in robots.txt — exactly the kind of thing a scanner finds |

## Step 1 — Start the test site standalone

```bash
cd genius-mirage-test-site
pip install -r requirements.txt
python seed_data.py
python app.py
```

Visit `http://127.0.0.1:5050` and confirm the site itself works — browse
products, log in as `demo` / `Demo1234!`, view an invoice. Do this **before**
wiring up Genius Mirage, so you know any flagged behaviour later is Genius
Mirage doing its job, not the site being broken.

## Step 2 — Register the site in Genius Mirage

1. Start your Genius Mirage backend (`python manage.py runserver`) and
   frontend as usual.
2. In the dashboard, register a new site:
   - Domain: `127.0.0.1:5050` (or `localhost:5050`)
   - This generates a `site_id` like `site-1781275269115`.
3. The site starts in `monitoring` status until the protection is confirmed
   installed (Step 4 makes this verifiable).

## Step 3 — Get your SDK credentials

Genius Mirage's SDK protects a site at the server level (this is the mode
that actually performs the backend swap — see the note on the JS snippet
below). Fetch your credentials:

```bash
curl -H "Authorization: Bearer <your_jwt_access_token>" \
     http://127.0.0.1:8000/api/auth/sites/<site_id>/sdk-config/
```

This returns:

```json
{
  "site_id": "site-1781275269115",
  "api_url": "http://127.0.0.1:8000",
  "api_token": "a1b2c3d4e5f6...",
  "usage": { "flask": "from genius_mirage_sdk.flask_sdk import init_genius_mirage\n..." }
}
```

Paste the three values into `config.py`:

```python
GENIUS_MIRAGE_SITE_ID   = 'site-1781275269115'
GENIUS_MIRAGE_API_URL   = 'http://127.0.0.1:8000'
GENIUS_MIRAGE_API_TOKEN = 'a1b2c3d4e5f6...'
```

Or export them as environment variables instead of editing the file:

```bash
export GM_SITE_ID='site-1781275269115'
export GM_API_URL='http://127.0.0.1:8000'
export GM_API_TOKEN='a1b2c3d4e5f6...'
```

Restart the Flask app. You should see in the console:

```
[Northbridge] Genius Mirage protection ENABLED — site_id=site-1781275269115
```

**This is the integration that actually performs the swap.** The SDK calls
Genius Mirage's `/api/swap/process/` on every request with the real method,
body, and headers — so SQL injection in a POST body, command injection in a
form field, and so on are all visible to the evaluator, not just GET query
strings.

## Step 4 — (Optional) Add the JS snippet for extra client-side telemetry

The JS snippet adds dwell-time tracking, navigation-pattern signals, and the
no-JS/honeypot-field traps — useful supplementary signal, but it **cannot
perform the swap on its own** (by the time a JS activity report reaches
Genius Mirage, the real backend has already answered that request). The SDK
in Step 3 is what does the actual swap; this step is optional.

```bash
curl -H "Authorization: Bearer <your_jwt_access_token>" \
     http://127.0.0.1:8000/api/auth/sites/<site_id>/snippet/v5/
```

Paste the returned `snippet` HTML into
`templates/genius_mirage_snippet.html`, replacing its placeholder comment.

## Step 5 — Verify the connection

In the Genius Mirage dashboard, trigger the site profiler (or visit the
site a few times normally first), then check the site's status flips from
`monitoring` to `active`.

## Step 6 — Test each vulnerability class

With both servers running, try each of the following against
`http://127.0.0.1:5050` and watch the Genius Mirage **Live Deception
Monitor** page. A flagged session should show its threat tier, score, and
(once decoyed) a live feed of what the decoy is feeding back to you.

**SQL injection** — Tier 1 (instant, deterministic):
```
http://127.0.0.1:5050/product/1 UNION SELECT id,name,category,price,description,sku,in_stock FROM products
http://127.0.0.1:5050/search?q=' OR '1'='1
```

**Path traversal** — Tier 1:
```
http://127.0.0.1:5050/download?file=../../etc/passwd
http://127.0.0.1:5050/download?file=../config.py
```

**Command injection** — Tier 1:
```
POST /support/tools/track   order_ref=ORD-100231; whoami
POST /support/tools/track   order_ref=ORD-100231 && cat /etc/passwd
```

**SSTI** — Tier 1/2 depending on payload:
```
POST /support/tools/preview   product_name={{7*7}}
POST /support/tools/preview   product_name={{config}}
```

**Credential brute force** — Tier 2 (behavioural — send several rapid
attempts to see the score accumulate):
```
POST /login   username=admin&password=wrong1
POST /login   username=admin&password=wrong2
... (repeat rapidly)
```

**IDOR / enumeration** — Tier 2 (sequential ID access pattern):
```
Logged in as demo, visit:
http://127.0.0.1:5050/account/invoice/1
http://127.0.0.1:5050/account/invoice/2
http://127.0.0.1:5050/account/invoice/3
http://127.0.0.1:5050/account/invoice/4   ← not yours
http://127.0.0.1:5050/account/invoice/5
http://127.0.0.1:5050/account/invoice/6
```

**Recon / scanning** — Tier 1/2:
```
http://127.0.0.1:5050/admin-portal
http://127.0.0.1:5050/.env
http://127.0.0.1:5050/wp-admin
```

**Ambiguous/borderline input** (use this to confirm Tier 3 / false-positive
handling — a real customer might plausibly type something like this):
```
http://127.0.0.1:5050/search?q=drop leaf table
```

## What to look for in the dashboard

- **Tier 1 hits** should be instant — the very first malicious request
  should flip `backend_type` to `deceptive` with no delay.
- **Tier 2 accumulation** — a single odd request (e.g. one failed login)
  should *not* flag the session; several in a short window should.
- **Tier 3 / AI** — ambiguous inputs should get a reasoned explanation in
  the session detail panel, not just a raw score.
- **The decoy feed** — once flagged, every further request from that
  session should show up in the Decoy Interaction Log tab, and the actual
  HTTP response your browser/curl receives should look plausible rather
  than an error page or a dropped connection.
- **No impact on the demo customer flow** — while testing attacks from one
  browser/terminal, browsing normally from another should remain completely
  unaffected (open a private/incognito window to confirm).

## Resetting between test runs

```bash
rm northbridge.db
python seed_data.py
```

This gives you fresh invoice IDs and a clean admin/demo account each time,
without needing to restart Genius Mirage itself.
