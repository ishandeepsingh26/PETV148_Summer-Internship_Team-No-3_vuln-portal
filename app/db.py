import os
import click
from flask import current_app, g

# ---------------------------------------------------------------------------
# Database backend selection
#
# Locally (or on any host with a writable filesystem) this uses SQLite, same
# as before. On Vercel — whose filesystem is read-only — set a DATABASE_URL
# env var pointing at a Postgres database and this module transparently
# switches over. No changes are needed in auth.py / vulnerabilities.py /
# reports.py: they all call db.execute("... ?", (...)) and read results via
# row["col"], and that same interface works against either backend thanks
# to the wrapper class below.
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3


class _PGConnWrapper:
    """Makes a psycopg2 connection look like the sqlite3.Connection API
    this app uses: .execute(sql, params) returning a cursor with
    .fetchone()/.fetchall(), plus .executescript() and .commit()."""

    def __init__(self, conn):
        self._conn = conn

    @staticmethod
    def _to_pg(sql):
        # This app only ever uses "?" as a placeholder character, so a
        # straight replace is safe here.
        return sql.replace("?", "%s")

    def execute(self, sql, params=()):
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(self._to_pg(sql), params)
        return cur

    def executescript(self, script):
        cur = self._conn.cursor()
        cur.execute(script)
        cur.close()
        self._conn.commit()

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            raw_conn = psycopg2.connect(DATABASE_URL)
            g.db = _PGConnWrapper(raw_conn)
        else:
            g.db = sqlite3.connect(current_app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    role TEXT NOT NULL DEFAULT 'analyst',  -- admin | analyst | viewer
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    asset_type TEXT,             -- web app, server, network device, etc.
    owner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    asset_id INTEGER REFERENCES asset(id) ON DELETE SET NULL,
    reported_by INTEGER REFERENCES user(id) ON DELETE SET NULL,
    assigned_to INTEGER REFERENCES user(id) ON DELETE SET NULL,

    -- CVSS v3.1 base metrics (raw vector components)
    cvss_av TEXT,   -- Attack Vector: N/A/L/P
    cvss_ac TEXT,   -- Attack Complexity: L/H
    cvss_pr TEXT,   -- Privileges Required: N/L/H
    cvss_ui TEXT,   -- User Interaction: N/R
    cvss_s  TEXT,   -- Scope: U/C
    cvss_c  TEXT,   -- Confidentiality: N/L/H
    cvss_i  TEXT,   -- Integrity: N/L/H
    cvss_a  TEXT,   -- Availability: N/L/H
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_vector TEXT,

    -- OWASP Risk Rating (likelihood x impact factors, 0-9 scale each)
    owasp_likelihood REAL,
    owasp_impact REAL,
    owasp_risk_score REAL,
    owasp_risk_level TEXT,

    status TEXT NOT NULL DEFAULT 'open',  -- open, in_progress, remediated, accepted_risk, false_positive
    remediation_notes TEXT,
    due_date DATE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id INTEGER REFERENCES vulnerability(id) ON DELETE CASCADE,
    changed_by INTEGER REFERENCES user(id) ON DELETE SET NULL,
    field_changed TEXT,
    old_value TEXT,
    new_value TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    asset_type TEXT,
    owner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerability (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    asset_id INTEGER REFERENCES asset(id) ON DELETE SET NULL,
    reported_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    assigned_to INTEGER REFERENCES "user"(id) ON DELETE SET NULL,

    cvss_av TEXT,
    cvss_ac TEXT,
    cvss_pr TEXT,
    cvss_ui TEXT,
    cvss_s  TEXT,
    cvss_c  TEXT,
    cvss_i  TEXT,
    cvss_a  TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_vector TEXT,

    owasp_likelihood REAL,
    owasp_impact REAL,
    owasp_risk_score REAL,
    owasp_risk_level TEXT,

    status TEXT NOT NULL DEFAULT 'open',
    remediation_notes TEXT,
    due_date DATE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_history (
    id SERIAL PRIMARY KEY,
    vuln_id INTEGER REFERENCES vulnerability(id) ON DELETE CASCADE,
    changed_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    field_changed TEXT,
    old_value TEXT,
    new_value TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db():
    db = get_db()
    if USE_POSTGRES:
        db.executescript(POSTGRES_SCHEMA)
    else:
        db.executescript(SQLITE_SCHEMA)
    db.commit()
    migrate_db()


def migrate_db():
    """Add columns introduced after initial release to existing databases."""
    db = get_db()
    if USE_POSTGRES:
        existing_columns = {
            row["column_name"]
            for row in db.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'user'"
            ).fetchall()
        }
    else:
        existing_columns = {row["name"] for row in db.execute("PRAGMA table_info(user)")}

    if "email" not in existing_columns:
        db.execute("ALTER TABLE user ADD COLUMN email TEXT")
    if "phone" not in existing_columns:
        db.execute("ALTER TABLE user ADD COLUMN phone TEXT")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email ON user(email)")
    db.commit()


def seed_admin():
    """
    Ensure exactly one Admin account exists. This is the ONLY way an admin
    account is ever created — there is no "add admin" button anywhere in the
    web app. Admin can only log in with these seeded credentials.

    Credentials come from environment variables so they aren't hardcoded:
        ADMIN_USERNAME (default: "admin")
        ADMIN_PASSWORD (default: "ChangeMe123!" — change this in production)
    """
    import os
    import bcrypt

    db = get_db()
    existing_admin = db.execute("SELECT id FROM user WHERE role = 'admin'").fetchone()
    if existing_admin:
        return

    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
    phone    = os.environ.get("ADMIN_PHONE", "+10000000000")

    clash = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
    if clash:
        db.execute("UPDATE user SET role = 'admin' WHERE id = ?", (clash["id"],))
        db.commit()
        print(f"[seed_admin] Existing account '{username}' promoted to Admin.")
        return

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db.execute(
        "INSERT INTO user (username, password_hash, phone, role) VALUES (?, ?, ?, 'admin')",
        (username, password_hash, phone),
    )
    db.commit()
    print("=" * 64)
    print(f"[seed_admin] Admin account ready — username: '{username}'")
    print(f"[seed_admin] Admin phone    : '{phone}'")
    if "ADMIN_PASSWORD" not in os.environ:
        print(f"[seed_admin] Using DEFAULT password: '{password}'")
        print("[seed_admin] Set the ADMIN_PASSWORD env var before deploying")
        print("[seed_admin] anywhere real, then restart the app.")
    if "ADMIN_PHONE" not in os.environ:
        print("[seed_admin] Set ADMIN_PHONE env var to your real phone number")
        print("[seed_admin] so 2FA OTP codes are delivered to you.")
    print("=" * 64)


@click.command("init-db")
def init_db_command():
    """Create database tables if they don't exist."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    with app.app_context():
        init_db()
        seed_admin()
