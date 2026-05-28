"""Seeded bug: pickle.loads on untrusted body."""
import pickle


def restore_session(body):
    return pickle.loads(body)
