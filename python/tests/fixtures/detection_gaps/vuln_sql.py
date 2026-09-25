import sqlite3

conn = sqlite3.connect("db")
cur = conn.cursor()
user_input = request.form["name"]

# G12 case 1: %-interpolation with NO space after % (old regex required one)
cur.execute(sql % user_input)

# G12 case 2: literal %-interpolation in the call
cur.execute("SELECT * FROM users WHERE name = %s" % user_input)

# G12 case 3: .format() on a variable assigned a {} template earlier
SQL = "SELECT * FROM users WHERE name = '{}'"
cur.execute(SQL.format(user_input))

# G12 case 4: template variable assigned a %-literal, sink line is bare ident
sql2 = "SELECT * FROM users WHERE name = '%s'" % user_input
cur.execute(sql2)

# G12 case 5: concatenation built then executed
sql3 = "SELECT * FROM users WHERE name = '" + user_input + "'"
cur.execute(sql3)

# SAFE (must NOT be flagged): parameterized queries
q2 = "SELECT * FROM t WHERE id = %s"
cur.execute(q2, (user_input,))
cur.execute("SELECT * FROM t WHERE id = ?", (user_input,))
cur.executemany(q2, [(1,), (2,)])
