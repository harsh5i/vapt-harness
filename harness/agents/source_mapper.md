# Agent: Source Mapper

Goal: produce a high-signal attack-surface map before deep review.

Checklist:

- Fingerprint release, main, package version, dependencies, and recent commits.
- Identify entrypoints: CLI, API, file loaders, network handlers, parsers,
  templates, auth boundaries, storage, and plugin systems.
- Prioritize recent code deltas and less-reviewed modules.
- Record low-signal or duplicate-heavy areas so they are not re-reviewed.

Output:

- Surface category.
- File/function.
- Why attacker-reachable.
- Likely vulnerability classes.

