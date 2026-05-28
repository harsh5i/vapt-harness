"""External security tooling wrappers (Phase 5 Move 3).

Each module exposes a thin function that builds the right argv for a
container-based or local-binary invocation of an external scanner, returns
the canonical container image, and lists capability flags. The harness CLI
glue (cmd_scan_<tool> in harness.py) calls these and pipes through the
existing `run_tool_scan` evidence pipeline.

Modules:

- container: shared helpers (image preflight, argv composition).
- zap: OWASP ZAP baseline + active scan.
- sqlmap: SQL injection detection in batch mode.
- jwt: JWT token inspection and weak-key probe.
- screenshot: Playwright-based visual capture.
"""
