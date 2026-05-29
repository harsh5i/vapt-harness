"""Seeded scaffold: route handlers with and without authz."""
from flask import Flask, request

app = Flask(__name__)


@app.route("/public/ping")
def ping():
    return "pong"


@app.route("/admin/users")
def admin_users():
    return list_users()


@app.route("/me")
@login_required  # noqa: F821
def me():
    return current_user_info()


def list_users():
    return []


def current_user_info():
    return {}
