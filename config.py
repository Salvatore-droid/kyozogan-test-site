"""
config.py
=========
Configuration for the Northbridge Office Supplies test site.

After registering this site in Genius Mirage, fetch your credentials with:

    curl -H "Authorization: Bearer <your_jwt_access_token>" \\
         http://127.0.0.1:8000/api/auth/sites/<site_id>/sdk-config/

...and paste the three values below.

Leave GENIUS_MIRAGE_SITE_ID empty to run the site standalone (no protection),
which is useful for confirming the site itself works before wiring it up.
"""

import os

# ── Flask ──────────────────────────────────────────────────────────────────
FLASK_SECRET_KEY = 'northbridge-dev-secret-key-change-me'
FLASK_PORT       = 5050
FLASK_DEBUG      = True

# ── Genius Mirage SDK ─────────────────────────────────────────────────────
# Fill these in after registering the site (see README.md, Step 2).
GENIUS_MIRAGE_SITE_ID   = os.environ.get('GM_SITE_ID',   '')
GENIUS_MIRAGE_API_URL   = os.environ.get('GM_API_URL',   'http://127.0.0.1:8000')
GENIUS_MIRAGE_API_TOKEN = os.environ.get('GM_API_TOKEN', '')
