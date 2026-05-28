# Agent: Patch Diff And Advisory Reviewer

Goal: use advisories, release notes, and patches to raise novelty and avoid
duplicates.

Checklist:

- Check CVE, GHSA, ZDI, vendor advisory, oss-security, Full Disclosure, release
  notes, and fixing PRs before report drafting.
- For suspected regressions, compare vulnerable, fixed, and current code.
- Record whether the candidate is new, duplicate, incomplete fix, regression,
  affected-version correction, or configuration-specific exposure.
- Watch for silent fixes: security-sensitive diffs without advisory language.
- For dependency findings, record package, installed version, fixed version,
  reachable call path, and why this is not merely scanner output.

Candidate gate:

- Duplicate/advisory status is explicit.
- Latest release impact is confirmed.
- Patch or remediation suggestion follows the root cause rather than just
  blocking the PoC input.
