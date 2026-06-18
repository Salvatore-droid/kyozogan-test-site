"""
app.py
======
Northbridge Office Supplies — a small office-supplies storefront used as a
LOCAL TEST TARGET for exercising Genius Mirage's three-tier evaluation and
backend-swap functionality.

This app is intentionally a plain, unglamorous small-business site — not a
"CTF box" dressed up to look vulnerable. It does the kind of thing a real
small business commissions: a product catalog, a login, an account/invoice
area, a contact form, and a couple of "self-service tools" pages. Underneath,
several of these features are implemented the way an under-resourced agency
might actually write them — which is to say, with real, unintentional-looking
security gaps:

  /product/<id>            — numeric ID lookup, naive SQL string formatting   → SQL injection
  /search?q=                — same naive SQL formatting on the search box     → SQL injection
  /login                    — plaintext password comparison, no rate limit    → credential brute force
  /account/invoice/<id>     — sequential numeric IDs, no ownership check      → IDOR
  /support/tools/track      — order ref interpolated into a "log line"        → log/command injection vector
  /support/tools/preview    — product name rendered through Jinja from_string→ SSTI
  /download?file=           — naive os.path.join with user input             → path traversal
  /admin-portal              — unlinked (robots.txt disallow only), plaintext creds → recon + brute force

None of this is exotic — it is the standard small-site vulnerability set,
on purpose, so Genius Mirage's evaluator has real attack classes to flag
rather than contrived ones.

Run:
    pip install -r requirements.txt
    python seed_data.py
    python app.py
"""

import os
import re
import sqlite3
import subprocess
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, abort, g,
)
from jinja2 import Environment

import config

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

DB_PATH        = os.path.join(os.path.dirname(__file__), 'northbridge.db')
BROCHURE_DIR   = os.path.join(os.path.dirname(__file__), 'brochures')

# ── Optional Genius Mirage protection ───────────────────────────────────────
# If GENIUS_MIRAGE_SITE_ID is set in config.py, install the SDK middleware.
# Until then, the site simply runs unprotected — useful for confirming the
# site itself works before wiring up protection (see README.md).
if config.GENIUS_MIRAGE_SITE_ID:
    from genius_mirage_sdk.flask_sdk import init_genius_mirage
    init_genius_mirage(
        app,
        site_id=config.GENIUS_MIRAGE_SITE_ID,
        api_url=config.GENIUS_MIRAGE_API_URL,
        api_token=config.GENIUS_MIRAGE_API_TOKEN,
    )
    print(f"[Northbridge] Genius Mirage protection ENABLED — site_id={config.GENIUS_MIRAGE_SITE_ID}")
else:
    print("[Northbridge] Running WITHOUT Genius Mirage protection "
          "(GM_SITE_ID not set — see README.md Step 2/3).")


# ── DB helpers ───────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# ── Routes: storefront ──────────────────────────────────────────────────────

@app.route('/')
def home():
    db = get_db()
    products = db.execute(
        "SELECT * FROM products ORDER BY id LIMIT 8"
    ).fetchall()
    return render_template('index.html', products=products, active='home')


@app.route('/shop')
def shop():
    db = get_db()
    category = request.args.get('category', '').strip()
    categories = [r['category'] for r in db.execute(
        "SELECT DISTINCT category FROM products ORDER BY category"
    ).fetchall()]

    if category:
        products = db.execute(
            "SELECT * FROM products WHERE category = ? ORDER BY id", (category,)
        ).fetchall()
    else:
        products = db.execute("SELECT * FROM products ORDER BY id").fetchall()

    return render_template(
        'shop.html', products=products, categories=categories,
        category=category, active='shop',
    )


@app.route('/product/<product_id>')
def product_detail(product_id):
    """
    Vulnerable surface: SQL injection.

    The product ID is concatenated directly into the SQL string rather than
    using a parameterised query — a real (and common) mistake when a
    "quick lookup by ID" route gets written without much thought, e.g. by
    someone copy-pasting a pattern that worked for an internal admin script.

    Try:
      /product/1
      /product/1 OR 1=1
      /product/1 UNION SELECT id,name,category,price,description,sku,in_stock FROM products
    """
    db = get_db()
    query = f"SELECT * FROM products WHERE id = {product_id}"
    try:
        product = db.execute(query).fetchone()
    except sqlite3.Error:
        product = None

    reviews = []
    if product:
        reviews = db.execute(
            "SELECT * FROM reviews WHERE product_id = ? ORDER BY id", (product['id'],)
        ).fetchall()

    return render_template('product.html', product=product, reviews=reviews, active='shop')


@app.route('/search')
def search():
    """
    Vulnerable surface: SQL injection via the search box.

    Same class of bug as /product/<id> but via a LIKE clause built with an
    f-string — another very common real-world pattern.
    """
    db = get_db()
    q = request.args.get('q', '').strip()
    products = []
    if q:
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        try:
            products = db.execute(query).fetchall()
        except sqlite3.Error:
            products = []
    return render_template('search.html', products=products, query=q, active='shop')


# ── Routes: auth / account ──────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Vulnerable surface: credential brute force.

    Plaintext password comparison, no lockout, no rate limiting, no CAPTCHA —
    deliberately so this route is a realistic brute-force target.
    """
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and user['password'] == password:
            session['user_id'] = user['id']
            return redirect(url_for('account'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error, active='login')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))


@app.route('/account')
def account():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    invoices = db.execute(
        "SELECT * FROM invoices WHERE user_id = ? ORDER BY id DESC", (session['user_id'],)
    ).fetchall()
    return render_template('account.html', user=user, invoices=invoices, active='account')


@app.route('/account/invoice/<int:invoice_id>')
def view_invoice(invoice_id):
    """
    Vulnerable surface: Insecure Direct Object Reference (IDOR).

    Sequential small integer IDs, and no check that the invoice belongs to
    the logged-in user — a logged-in customer can simply change the number
    in the URL and view someone else's invoice.
    """
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db()
    invoice = db.execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    return render_template('invoice.html', invoice=invoice, active='account')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    sent = False
    if request.method == 'POST':
        sent = True
    return render_template('forgot_password.html', sent=sent)


# ── Routes: static content ──────────────────────────────────────────────────

@app.route('/about')
def about():
    return render_template('about.html', active='about')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    sent = False
    if request.method == 'POST':
        sent = True
    return render_template('contact.html', sent=sent, active='contact')


# ── Routes: self-service tools ──────────────────────────────────────────────

@app.route('/support/tools')
def support_tools():
    return render_template('tools.html')


@app.route('/support/tools/track', methods=['POST'])
def track_order():
    """
    Vulnerable surface: command/log injection.

    The order reference is passed to a shell command (a stand-in for a
    "check delivery status via a legacy shell script" integration — a
    pattern that genuinely exists at small logistics-adjacent businesses).
    Input is interpolated into the shell command without sanitisation.

    Try:
      ORD-100231
      ORD-100231; whoami
      ORD-100231 && cat /etc/passwd
      ORD-100231 | id
    """
    order_ref = request.form.get('order_ref', '')
    try:
        # Deliberately naive: shell=True with the value interpolated directly
        # into the command line (no quoting), so shell metacharacters in
        # order_ref (;, &&, |, $(), backticks) are interpreted by the shell
        # rather than treated as literal text.
        result = subprocess.run(
            "echo Checking status for order: " + order_ref,
            shell=True, capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.strip() or result.stderr.strip()
        output += "\nStatus: In transit — expected delivery within 2 business days."
    except Exception as exc:
        output = f"Error checking order status: {exc}"

    return render_template(
        'tools.html', track_input=order_ref, track_output=output,
    )


@app.route('/support/tools/preview', methods=['POST'])
def preview_product():
    """
    Vulnerable surface: Server-Side Template Injection (SSTI).

    The product name is rendered through Jinja2's Environment().from_string,
    a real (if ill-advised) way someone might implement a "quick templated
    preview message" feature without realising user input shouldn't be
    treated as template source.

    Try:
      Office Chair
      {{ 7*7 }}
      {{ config }}
      {{ self.__init__.__globals__ }}
    """
    product_name = request.form.get('product_name', '')
    try:
        env = Environment()
        template = env.from_string(
            f"<strong>Preview:</strong> A quick look at &quot;{product_name}&quot; "
            f"will be included in our next printed catalog edition."
        )
        output = template.render()
    except Exception as exc:
        output = f"Could not generate preview: {exc}"

    return render_template(
        'tools.html', preview_input=product_name, preview_output=output,
    )


@app.route('/download')
def download():
    """
    Vulnerable surface: path traversal.

    The requested filename is joined onto BROCHURE_DIR with plain string
    concatenation rather than a safe-join / allow-list check.

    Try:
      catalog.pdf
      ../app.py
      ../../northbridge.db
      ../config.py
    """
    filename = request.args.get('file', 'catalog.pdf')
    file_path = BROCHURE_DIR + '/' + filename   # deliberately naive join
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'application/octet-stream'}
    except Exception:
        abort(404)


# ── Routes: hidden admin (recon target) ─────────────────────────────────────

@app.route('/admin-portal', methods=['GET', 'POST'])
def admin_portal():
    """
    Unlinked admin login — not in any visible nav, only disallowed in
    robots.txt (which itself is a hint to a scanner that something lives
    here). Plaintext comparison, no lockout — a realistic recon + brute
    force target.
    """
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        admin = db.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
        if admin and admin['password'] == password:
            session['admin_id'] = admin['id']
            return f"<h1>Welcome, {username}.</h1><p>(Demo admin area — not implemented further.)</p>"
        error = 'Invalid credentials.'
    return render_template('admin_portal.html', error=error)


@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')


# ── Error handling ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("[Northbridge] No database found — run `python seed_data.py` first.")
    app.run(host='127.0.0.1', port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
