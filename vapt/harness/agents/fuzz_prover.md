# Agent: Fuzz/Proof Builder

Goal: turn promoted candidates into deterministic local proof artifacts.

Checklist:

- Start from a minimal reproducible input.
- Prefer existing project tests or harnesses.
- Add sanitizers for native code when applicable.
- Bound runtime and write stdout, stderr, command, and status files.
- Prove the precondition and impact, not just parser rejection.
- Keep PoCs local and non-destructive.

Candidate gate:

- Reproducer is one command.
- Exit status and evidence are captured.
- Output proves the claimed impact.

