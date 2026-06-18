"""
seed_data.py
============
Creates and seeds northbridge.db with a small product catalog, demo customer
account, invoices, and an admin account.

Run once before starting the app:
    python seed_data.py
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'northbridge.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    price       REAL NOT NULL,
    description TEXT NOT NULL,
    sku         TEXT NOT NULL,
    in_stock    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS reviews (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    author     TEXT NOT NULL,
    body       TEXT NOT NULL,
    rating     INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    email     TEXT NOT NULL,
    full_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    order_ref  TEXT NOT NULL,
    total      REAL NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    items      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
"""

PRODUCTS = [
    ('A4 Recycled Copy Paper (Box of 5 Reams)', 'Paper & Printing', 24.99,
     'Bright white 80gsm recycled copy paper, 500 sheets per ream, 5 reams per box. Suitable for laser and inkjet printers.',
     'NB-PP-1001', 1),
    ('Ergonomic Mesh Office Chair', 'Office Furniture', 189.00,
     'Adjustable lumbar support, breathable mesh back, height-adjustable armrests. Rated for up to 120kg.',
     'NB-FN-2003', 1),
    ('Wireless Ergonomic Keyboard & Mouse Combo', 'Tech & Accessories', 42.50,
     'Low-profile wireless keyboard with numeric pad and a contoured wireless mouse. 2.4GHz, includes USB receiver.',
     'NB-TC-3010', 1),
    ('Premium Ballpoint Pens (Pack of 12)', 'Stationery', 8.99,
     'Smooth-writing 1.0mm ballpoint pens in black ink. Comfortable grip, retractable tip.',
     'NB-ST-4002', 1),
    ('Heavy-Duty Lever Arch Files (Pack of 10)', 'Stationery', 19.99,
     'A4 lever arch binders with reinforced spine and metal corner protectors. Assorted colours.',
     'NB-ST-4015', 1),
    ('Adjustable Standing Desk Converter', 'Office Furniture', 129.00,
     'Sit-stand desk converter with gas-spring height adjustment and a dedicated keyboard tray.',
     'NB-FN-2011', 1),
    ('USB-C Docking Station (10-in-1)', 'Tech & Accessories', 56.00,
     'HDMI, USB-A x3, USB-C, SD card reader, Ethernet, and 100W PD pass-through in a compact aluminium housing.',
     'NB-TC-3022', 1),
    ('Whiteboard with Stand (120 x 90cm)', 'Office Furniture', 74.50,
     'Magnetic dry-erase whiteboard on a height-adjustable rolling stand. Includes marker tray.',
     'NB-FN-2020', 0),
]

REVIEWS = [
    (1, 'Mercy W.', 'Good quality paper, no jamming in our office printer so far.', 5),
    (1, 'Tom O.', 'Slightly thinner than the previous brand we used but works fine.', 4),
    (2, 'Janet K.', 'Very comfortable for long work days. Assembly took about 20 minutes.', 5),
    (2, 'David M.', 'Armrests squeak a little after a few weeks but otherwise great.', 4),
    (3, 'Brian A.', 'Battery life on the mouse is excellent. Keyboard feels a bit mushy.', 3),
    (4, 'Grace N.', 'Reliable pens, ordered a second pack already.', 5),
    (5, 'Peter S.', 'Sturdy binders, good for archiving client files.', 4),
    (7, 'Lucy R.', 'Docking station works well with my laptop, all ports detected immediately.', 5),
]

USERS = [
    ('demo', 'Demo1234!', 'demo@example.com', 'Demo Customer'),
]

# Invoice IDs are intentionally sequential and small (3-4 digits) so that
# /account/invoice/<id> enumeration is realistic to test.
INVOICES = [
    (1, 'ORD-100231', 58.97, 'paid',    '2026-04-02', '2x A4 Recycled Copy Paper, 1x Premium Pens'),
    (2, 'ORD-100245', 189.00, 'paid',   '2026-04-18', '1x Ergonomic Mesh Office Chair'),
    (3, 'ORD-100258', 42.50, 'pending', '2026-05-03', '1x Wireless Ergonomic Keyboard & Mouse Combo'),
    # The following belong to OTHER (fake) customers — used to demonstrate IDOR
    (4, 'ORD-100271', 129.00, 'paid',   '2026-05-10', '1x Adjustable Standing Desk Converter'),
    (5, 'ORD-100284', 74.50,  'paid',   '2026-05-22', '1x Whiteboard with Stand'),
    (6, 'ORD-100299', 56.00,  'paid',   '2026-06-01', '1x USB-C Docking Station'),
]

ADMINS = [
    ('admin', 'N0rthBr1dge2024!'),
]


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    conn.executemany(
        "INSERT INTO products (name, category, price, description, sku, in_stock) VALUES (?, ?, ?, ?, ?, ?)",
        PRODUCTS,
    )

    for product_id, author, body, rating in REVIEWS:
        conn.execute(
            "INSERT INTO reviews (product_id, author, body, rating, created_at) VALUES (?, ?, ?, ?, ?)",
            (product_id, author, body, rating, datetime.now().strftime('%Y-%m-%d')),
        )

    conn.executemany(
        "INSERT INTO users (username, password, email, full_name) VALUES (?, ?, ?, ?)",
        USERS,
    )

    conn.executemany(
        "INSERT INTO invoices (user_id, order_ref, total, status, created_at, items) VALUES (?, ?, ?, ?, ?, ?)",
        INVOICES,
    )

    conn.executemany(
        "INSERT INTO admins (username, password) VALUES (?, ?)",
        ADMINS,
    )

    conn.commit()
    conn.close()
    print(f"Database seeded at {DB_PATH}")
    print(f"  Demo customer login: demo / Demo1234!")
    print(f"  Admin login (hidden, /admin-portal): admin / N0rthBr1dge2024!")


if __name__ == '__main__':
    main()
