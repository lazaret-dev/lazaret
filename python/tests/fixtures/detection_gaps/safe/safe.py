import sqlite3

conn = sqlite3.connect("db")
cur = conn.cursor()
uid = 1

# SAFE: parameterized — the only idioms Lazaret should ever endorse
cur.execute("SELECT * FROM t WHERE id = ?", (uid,))
cur.executemany("INSERT INTO t VALUES (%s)", [(i,) for i in range(3)])

q = "SELECT * FROM t WHERE id = %s"
cur.execute(q, (uid,))

# SAFE: static query (identifier with no % / {} template behind it)
STATIC = "SELECT 1"
cur.execute(STATIC)

# SAFE: template with neither % nor {} executed directly
plain = "SELECT count(*) FROM t"
cur.execute(plain)
