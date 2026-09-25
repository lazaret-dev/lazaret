import requests
from flask import request, redirect

def fetch_profile():
    user_id = request.args.get("id")
    profile_url = request.args.get("url")
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    data = requests.get(profile_url)
    filename = request.args.get("f")
    fh = open("/data/" + filename)
    return redirect(request.args.get("next"))

def suppressed_example():
    import subprocess
    subprocess.run(cmd, shell=True)  # nosec
