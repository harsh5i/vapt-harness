# SSRF / Outbound Request Boundary

Thesis shape:

- Attacker controls a URL, host, registry, webhook, redirect, or integration
  endpoint.
- The server performs an outbound request across a trust boundary.
- Network restrictions, scheme restrictions, DNS rebinding protections, or
  redirect checks are missing or inconsistent.

Required proof:

- Captive listener or local controlled service receives the request.
- Internal/reserved address controls are tested where safe and authorized.
- Redirect and DNS behavior are recorded when relevant.
- No scanning of unrelated third-party infrastructure.

Common sinks:

- `requests`, `httpx`, `aiohttp`, `urllib`, Go `net/http`, JS `fetch`/`axios`.
- Registry pull clients.
- Link preview/unfurl fetchers.
- Webhook dispatchers.
