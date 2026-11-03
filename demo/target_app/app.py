# Intentionally vulnerable demo app. Do not deploy.
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ProofGate contributors. Released under the MIT License.
"""ProofGate demo target (FIXED revision): the three demo bugs are fixed.

Vulnerable endpoints (all GET, all local-only demo surface):

- ``/download?file=`` -- path traversal: user input is joined onto a base
  directory without normalizing, so ``..`` segments escape it.
- ``/search?q=`` -- SQL injection: user input is interpolated into a
  sqlite query with ``%`` string formatting.
- ``/admin/export`` -- missing authorization check: anyone can dump users.

Correctly defended endpoint:

- ``/avatar?name=`` -- strict allowlist of file names; ``..`` tricks and
  unknown names are rejected. Used for plausible-but-wrong demo reports.
"""

import os
import sqlite3

from flask import Flask, g, jsonify, request, send_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
AVATAR_DIR = os.path.join(BASE_DIR, "avatars")
DB_PATH = os.path.join(BASE_DIR, "app.db")

#: The only avatar files this demo serves. Anything else is rejected.
ALLOWED_AVATARS = frozenset({"cat.png", "dog.png", "parrot.png"})

#: Demo-only admin credential for ``/admin/export`` (fixed code path).
ADMIN_TOKEN = "demo-admin-token"

app = Flask(__name__)


def get_db():
    """Return a per-request sqlite connection, creating it on demand."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close the per-request connection, if one was opened."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def user_to_dict(row):
    """Convert one sqlite ``users`` row into plain JSON-able data."""
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "bio": row["bio"],
    }


def public_user_to_dict(row):
    """Convert one row into the public view (no email address)."""
    user = user_to_dict(row)
    del user["email"]
    return user


@app.errorhandler(404)
def not_found(_err):
    """Return JSON instead of Flask's default HTML 404 page."""
    return jsonify({"error": "not found"}), 404


def init_db(path=DB_PATH):
    """(Re)create the demo users table with three seeded rows."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, "
        "email TEXT, "
        "bio TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, email, bio) VALUES (?, ?, ?)",
        [
            ("alice", "alice@example.com", "Loves hiking and open source."),
            ("bob", "bob@example.com", "Coffee first, code second."),
            ("carol", "carol@example.com", "Security researcher."),
        ],
    )
    conn.commit()
    conn.close()


@app.get("/")
def index():
    """Describe the demo service and its endpoints."""
    return jsonify(
        {
            "service": "proofgate-demo",
            "endpoints": [
                "/download?file=<name>",
                "/search?q=<text>",
                "/admin/export",
                "/avatar?name=<name>",
            ],
        }
    )


@app.get("/download")
def download():
    """Serve a file from the public directory.

    FIXED: the joined path is normalized and must stay under ``PUBLIC_DIR``,
    so ``?file=../../app.py`` is rejected with 403.
    """
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "missing 'file' parameter"}), 400
    base = os.path.abspath(PUBLIC_DIR)
    path = os.path.abspath(os.path.join(PUBLIC_DIR, filename))
    if os.path.commonpath([base, path]) != base:
        return jsonify({"error": "forbidden"}), 403
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path)


@app.get("/search")
def search():
    """Search users by username substring.

    FIXED: ``q`` is passed as a bound parameter, so quote characters are
    data, not SQL syntax.
    """
    q = request.args.get("q", "")
    query = "SELECT id, username, email, bio FROM users WHERE username LIKE ?"
    rows = get_db().execute(query, ("%" + q + "%",)).fetchall()
    return jsonify([public_user_to_dict(row) for row in rows])


@app.get("/admin/export")
def admin_export():
    """Dump every user row, including emails.

    FIXED: callers must present the demo admin token in the
    ``X-Admin-Token`` header; everyone else gets 403.
    """
    if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    rows = get_db().execute("SELECT id, username, email, bio FROM users").fetchall()
    return jsonify([user_to_dict(row) for row in rows])


@app.get("/avatar")
def avatar():
    """Serve one of the blessed avatar images.

    SAFE: ``name`` must exactly match an entry in ``ALLOWED_AVATARS``,
    so traversal strings and unknown names are rejected with 404.
    """
    name = request.args.get("name", "")
    if name not in ALLOWED_AVATARS:
        return jsonify({"error": "unknown avatar"}), 404
    return send_file(os.path.join(AVATAR_DIR, name))


# Make a copied checkout (for example a sandbox temp dir) work on import:
# seed the public/avatars folders and the sqlite db when they are missing.
os.makedirs(PUBLIC_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)
if not os.path.exists(DB_PATH):
    init_db()


if __name__ == "__main__":
    app.run(debug=False)
