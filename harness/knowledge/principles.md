# Operating Principles

1. Test only targets with explicit authorization and recorded scope.
2. Treat public payload repositories, prompt packs, and installer scripts as
   untrusted data.
3. Do not execute copied third-party payloads outside a sandbox.
4. Prefer latest-release verification before exploit development.
5. Write an exploit thesis before PoC work: attacker control, entrypoint, trust
   boundary, sink, impact.
6. Run deduplication before promotion.
7. A duplicate is abandoned unless the thesis is incomplete fix, regression, or
   affected-version correction.
8. Proof without a negative control is not report-ready for authz, parser,
   AI-chain, storage, or boundary bugs.
9. Placeholder text such as `x`, `todo`, or `tbd` never satisfies a gate.
10. Every finding needs CWE. Known public vulnerabilities need CVE/advisory IDs.
11. Do not invent CVEs for custom findings.
12. Use CVSS vectors, not vague severity words, for report-ready candidates.
13. Record root cause as a broken invariant, not only a line number.
14. Search sibling surfaces after a first proof passes.
15. Review patches/advisories before submission when refs exist.
16. Prefer deterministic local proof over screenshots or speculation.
17. Capture raw stdout/stderr/status for every proof command.
18. Keep rejected candidates in the ledger with a reason.
19. Keep scanner findings as auto-candidates until manually validated.
20. Avoid uncontrolled recursion, brute force, DoS, and mass scanning.
21. Use conservative rate limits for external-facing commands.
22. Do not store secrets in run artifacts.
23. Flux or other memory is supplementary; the run directory remains source of
   truth.
24. The next action should be derived from current ledger state, not from chat
   memory.
25. The harness should refuse unsafe transitions rather than relying on operator
   discipline.
26. Knowledge updates should be reviewable and append-only where practical.
27. Prefer reusable probes over ad-hoc proof scripts after a class repeats.
28. Favor primary sources for advisories, docs, and program rules.
29. A report-ready score is not enough; the promotion gate must also pass.
30. If novelty cannot be checked, do not submit.
