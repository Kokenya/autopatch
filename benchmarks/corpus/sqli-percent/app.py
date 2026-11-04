import sqlite3
_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE users (name TEXT, role TEXT)")
_db.execute("INSERT INTO users VALUES ('alice', 'admin'), ('bob', 'user')")


def find_user(name):
    cur = _db.cursor()
    cur.execute("SELECT name, role FROM users WHERE name = '%s'" % name)
    return cur.fetchone()
