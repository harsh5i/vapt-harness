# VAPT Capability Assessment

Date: 2026-05-15
Environment: workspace-local `.venv-vapt`, `.vapt-bin`, `.vapt-home`

## Short Answer

The current environment is capable of strong authorized outside-in blackbox web
VA, including deep enumeration and low-rate vulnerability checks. It is not yet
a complete full-spectrum penetration testing lab.

"Full-fledged VA/PT" depends on scope. For public web blackbox work, the core
coverage is good. For authenticated application testing, exploit validation,
API testing, mobile, cloud, AD/internal network, wireless, container/Kubernetes,
and exploit-development workflows, more tooling and target-specific setup are
required.

## Current Strengths

| Area | Current Coverage |
| --- | --- |
| DNS/subdomain recon | `amass`, `subfinder`, `dnsx` |
| HTTP probing/tech detection | ProjectDiscovery `httpx`, `wafw00f`, `katana` |
| TLS assessment | `sslyze`, `testssl.sh`, `tlsx` |
| Web server checks | `nikto`, `shcheck.py`, `nuclei` |
| Content discovery | `ffuf`, `feroxbuster`, `dirsearch` |
| Web scanner coverage | `wapiti`, `nuclei`, `nikto` |
| Focused XSS testing | `dalfox` |
| Parameter discovery | `arjun` |
| Secret/dependency checks | `trufflehog`, `detect-secrets`, `pip-audit`, `bandit` |
| Manual proxy support | `mitmproxy` |
| Network/service checks | `nmap`, `naabu` |
| Guarded execution | `vapt/scripts/vapt_blackbox_guarded.sh` with timeouts/status logs |

## Gaps For Full-Spectrum PT

| Gap | Why It Matters | Suggested Tooling / Setup |
| --- | --- | --- |
| Interactive web proxy suite | Manual authenticated testing, replay, active checks, auth/session analysis | OWASP ZAP, Burp Suite Community/Pro if licensed |
| SQL injection validation | Focused SQLi confirmation beyond template findings | `sqlmap`, used only with ROE-approved request limits |
| Historical URL collection | More complete content discovery from archives | `gau`, `waybackurls`, `uro`, `unfurl` |
| Large wordlists | Better discovery coverage | SecLists, target-specific dictionaries |
| Screenshot/visual recon | Triage exposed apps and login panels | `gowitness` or equivalent browser-based screenshot tooling |
| API testing | OpenAPI/Postman-driven checks and auth-aware tests | ZAP API import, Schemathesis, Postman/Newman |
| JWT/OAuth testing | Token and auth flow assessment | `jwt_tool`, Burp/ZAP extensions |
| Request smuggling/desync | Specialized HTTP parser mismatch checks | Dedicated smuggling tooling, only under explicit ROE |
| JavaScript analysis | Endpoint/secret extraction from client bundles | LinkFinder/SecretFinder-style tooling or custom scripts |
| Containerized fallbacks | Reproducible tools with fragile dependencies | Docker images for ZAP, sqlmap, nuclei, legacy Python tools |
| Legacy DNS tooling | `dnsrecon` currently broken on Python 3.14 | Separate Python 3.11/3.12 venv or container |
| Exploit framework | Controlled exploit validation in permitted scopes | Metasploit only where ROE permits |
| Reporting automation | Consistent evidence-to-finding workflow | Local report generator over evidence/status files |

## Operating Position

Use this environment today for:

- Outside-in blackbox web VA.
- CDN/WAF-aware web surface checks.
- TLS/header/cookie/configuration assessment.
- Bounded crawling and content discovery.
- Low-rate nuclei/nikto/wapiti checks.
- Source and dependency checks when code is available.

Do not describe it as complete for:

- Internal network penetration tests.
- Authenticated web application PT without proxy/browser setup.
- API PT without OpenAPI/Postman collections or credentials.
- Cloud account reviews.
- Active exploit validation.
- Mobile, thick-client, wireless, AD, or Kubernetes assessments.

## Next Onboarding Backlog

Phase 5 Move 3 (2026-05-28) wired container-first wrappers for ZAP,
sqlmap, JWT, and screenshot under `vapt/harness/tools/`. Items marked
WIRED below mean the harness CLI knows how to invoke them via Docker/Podman
or a local binary, and reports `unavailable` cleanly when neither exists.

`harness tools-capability --json` reports current local mode per tool.

Priority 1:

- WIRED OWASP ZAP (baseline + full): `harness scan-zap-baseline`,
  `harness scan-zap-full`. Container image `ghcr.io/zaproxy/zaproxy:stable`.
  Install Docker/Podman or expose `zap-baseline.py` on PATH to activate.
- WIRED `sqlmap`: `harness scan-sqlmap`. Container image
  `paoloo/sqlmap:latest`. `pip install sqlmap` in `.venv-vapt` also works.
- Install SecLists.
- Install `gau`, `waybackurls`, `uro`, and `unfurl`.
- Add a curated nuclei template allowlist and update procedure.
- Add a YAML ROE file per target and make the guarded runner read it.

Priority 2:

- WIRED screenshot: `harness scan-screenshot`. Container image
  `mcr.microsoft.com/playwright/python:v1.45.0-jammy`. Playwright local
  install at `.venv-vapt/bin/playwright` is detected and used.
- Add API testing support: Schemathesis and Newman.
- WIRED JWT: `harness scan-jwt` does structural decode locally (no
  dependencies) and surfaces `alg=none`, `kid` path injection, and
  external-key-URL risks. Optional container call to `ticarpi/jwt_tool`
  for full toolkit when Docker is available.
- Container fallbacks landed via `tools/container.py` argv composer
  (Docker/Podman). Refusal records cite the canonical image so the
  capability gap is documented per refusal.
- Add report generation from evidence directories.

Priority 3:

- Add exploit-framework support only when explicit ROE permits it.
- Add cloud-specific tooling only for cloud-scope engagements.
- Add internal-network tooling only for internal-scope engagements.

## Rule

No environment is "fully onboarded" in the abstract. Before each engagement,
compare the ROE, target type, authorization level, and test depth against this
capability file, then update the tooling backlog and test plan.
