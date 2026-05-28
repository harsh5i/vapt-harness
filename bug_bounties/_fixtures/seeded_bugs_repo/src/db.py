"""Seeded bug: SQL injection via f-string formatting."""


def find_user(cursor, user_id):
    return cursor.execute(f"SELECT name, email FROM users WHERE id = {user_id}")
