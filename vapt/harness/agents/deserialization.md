# Agent: Deserialization Reviewer

Goal: find archive, object reconstruction, trusted-type, and parser issues with
concrete impact.

Checklist:

- Identify all load/loads/from-file APIs.
- Map attacker-controlled file members or schema fields.
- Determine default trusted types and user-supplied trust overrides.
- Look for imports, constructors, `__setstate__`, `__reduce__`, eval, template,
  or command execution before audit.
- Check helper/CLI flows that auto-trust or call the loader on behalf of users.
- Reject generic "loading untrusted files is dangerous" unless a trust bypass or
  default-impact path is proven.

Candidate gate:

- Latest release affected.
- Crafted serialized input controls the vulnerable path.
- Impact is RCE, file read/write, SSRF, auth bypass, or memory corruption.

