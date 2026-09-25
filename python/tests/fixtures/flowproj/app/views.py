from flask import request
from app import db

def profile():
    uid = request.args.get("id")
    return db.fetch(uid)
