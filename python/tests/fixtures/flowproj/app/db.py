import sqlite3
conn = sqlite3.connect("app.db")

def fetch(q):
    cur = conn.cursor()
    cur.execute(q)
    return cur.fetchone()
