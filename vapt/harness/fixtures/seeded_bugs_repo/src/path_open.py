"""Seeded bug: unguarded path open from user-shaped input."""


def serve_file(request):
    path = request.args.get("path") + ".txt"
    with open(path, "rb") as fh:
        return fh.read()
