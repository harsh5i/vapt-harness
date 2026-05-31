"""Import-surface regression tests.

After the strangler-fig decomposition, the harness package surface lives in
small modules (atomic_io, core, gates/, ledger/, ...) and is re-exported via
harness.py. These tests pin the public surfaces that downstream callers depend
on so a future refactor that accidentally drops a re-export fails loudly.
"""


def test_atomic_io_exposes_lock_primitives():
    import atomic_io

    assert hasattr(atomic_io, "file_lock"), "atomic_io.file_lock missing"
    assert hasattr(atomic_io, "candidate_ledger_lock"), "atomic_io.candidate_ledger_lock missing"


def test_harness_exposes_parser_builder():
    import harness

    assert hasattr(harness, "build_parser"), "harness.build_parser missing"


def test_harness_does_not_reimport_fcntl():
    """harness.py owned a stray `import fcntl` after decomposition; locking now
    lives in atomic_io. Pin its absence so the import doesn't sneak back in.
    """
    import harness

    assert not hasattr(harness, "fcntl"), "harness.py should not import fcntl directly"


def test_gates_authorization_surface():
    from gates.authorization import AuthorizationError, authorize, evaluate

    assert callable(authorize)
    assert callable(evaluate)
    assert issubclass(AuthorizationError, Exception)
