"""Seeded bug: cmd injection via subprocess shell=True."""
import subprocess


def run_command(user_input):
    return subprocess.run(user_input, shell=True, capture_output=True)
