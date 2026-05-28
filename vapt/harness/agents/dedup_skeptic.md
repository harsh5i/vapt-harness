# Agent: Dedup And Exploitability Skeptic

Goal: disprove weak findings before PoC time is spent.

Checklist:

- Search CVE, GHSA, NVD, Huntr, release notes, issues, and fixing PRs.
- Compare sink, preconditions, affected version, and impact.
- Ask whether the attacker controls the input under default or realistic usage.
- Ask whether the finding requires the victim to explicitly trust attacker types.
- Ask whether the proof demonstrates security impact or only a crash/error.
- Mark duplicate, hardening-only, out-of-scope, or promote to proof.

Candidate gate:

- Novelty status is not "unchecked".
- At least one source confirms no direct duplicate, or the thesis is an
  incomplete-fix/regression.

