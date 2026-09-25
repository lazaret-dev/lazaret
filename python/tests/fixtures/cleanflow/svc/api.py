from flask import request
from svc import store

def get_user():
    raw = request.args.get("id")
    uid = int(raw)              # sanitized to int
    return store.by_id(uid)

def search():
    term = request.args.get("q", "")
    return store.search(term)
