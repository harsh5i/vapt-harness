import os
import pickle
import requests
import subprocess
import yaml


def load_blob(path):
    data = pickle.load(open(path, "rb"))
    return yaml.load(data)


def fetch_url(url):
    return requests.get(url).text


def run_user_command(cmd):
    return subprocess.Popen(cmd, shell=True)


def write_named_file(name, body):
    with open("../" + name, "w") as fh:
        fh.write(body)


def render_template(env, text):
    return env.from_string(text).render()


def authz_check(user, obj):
    if not user.permission("view_secret"):
        raise PermissionError("denied")
    return obj.secret
