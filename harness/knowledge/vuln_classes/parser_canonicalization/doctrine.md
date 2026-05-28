# Parser Canonicalization

Thesis shape:

- Security checks and sink behavior interpret the same input differently.
- Normalization, decoding, path cleaning, URL parsing, or archive handling
  creates a bypass.
- The result crosses a file, tenant, origin, authz, or execution boundary.

Required proof:

- Benign normalized control.
- Malicious differential input.
- Evidence of checked representation versus sink representation.
- Clear target object reached outside intended boundary.

Common sinks:

- Archive extraction.
- Path joins and file writes.
- URL allowlists.
- Redirect URI and audience checks.
- Markdown/HTML/template renderers.
