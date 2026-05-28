# Seeded Bugs Repo

A captive fixture for source-reading probes (Phase 5 Move 5). Each file
intentionally contains one or more bug-class patterns the harness's
`source/ast_python.py` recognizes. The patch_variant_hunter probe runs
against this directory and should surface every seed.

Bug seeds:

- `src/cmd_runner.py` — `subprocess.run(user_input, shell=True)`.
- `src/yaml_loader.py` — `yaml.load(data)` without SafeLoader.
- `src/db.py` — `cursor.execute(f"SELECT ... {user_id}")`.
- `src/path_open.py` — `open(request.args.get("path"))` unguarded.
- `src/pickle_io.py` — `pickle.loads(body)`.

Do not "fix" these files; the harness uses them as known-positive
ground truth.
