"""Demo target: intentionally vulnerable helpers.

1. SQL injection (CWE-89) in the user lookup.
2. Path traversal (CWE-22) in the document reader.
"""

import os
import sqlite3

_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE users (name TEXT, role TEXT)")
_db.execute("INSERT INTO users VALUES ('alice', 'admin'), ('bob', 'user')")

DOCS = os.path.join(os.path.dirname(__file__), "docs")


def find_user(name):
    cur = _db.cursor()
    cur.execute(f"SELECT name, role FROM users WHERE name = '{name}'")
    return cur.fetchone()


def read_doc(name):
    with open(os.path.join(DOCS, name)) as f:
        return f.read()
