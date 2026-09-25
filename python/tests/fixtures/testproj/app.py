import os, pickle, hashlib
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "sup3rSecret42"

def get_user(cur, user_id):
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchone()

@app.route("/run")
def run_cmd():
    os.system("ping " + request.args.get("cmd"))
    return "ok"

try:
    risky()
except:
    pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
