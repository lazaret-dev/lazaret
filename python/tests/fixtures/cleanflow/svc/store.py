def by_id(uid):
    cur = _cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cur.fetchone()

def search(term):
    cur = _cursor()
    cur.execute("SELECT * FROM users WHERE name LIKE %s", (f"%{term}%",))
    return cur.fetchall()
