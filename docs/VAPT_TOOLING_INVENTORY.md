# VAPT Tooling Inventory

Last updated: 2026-05-26
Workspace: `vapt-harness`

## Environment Layout

- Python venv: `.venv-vapt`
- Python version: `Python 3.14.3`
- Python top-level requirements: `vapt/env/requirements-vapt.txt`
- Exact Python lock: `vapt/env/requirements-vapt.lock`
- Workspace tool bin: `.vapt-bin`
- Workspace tool home/config/cache: `.vapt-home`
- Activation helper: `vapt_env.sh`
- Dedicated activity folder: `vapt/`

Activate with:

```sh
. ./vapt_env.sh
```

This sets:

- `PATH="$PWD/.vapt-bin:/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH"`
- `HOME="$PWD/.vapt-home"`

The `HOME` override keeps ProjectDiscovery config/cache inside this workspace.

## Python Tools

Installed in `.venv-vapt`:

- `arjun==2.2.7`: parameter discovery
- `bandit==1.9.4`: Python SAST
- `detect-secrets==1.5.0`: secret detection
- `dirsearch==0.4.3.post1`: directory/content discovery
- `pip-audit==2.10.0`: Python dependency vulnerability audit
- `semgrep==1.163.0`: multi-language static analysis
- `shcheck==1.7`: HTTP security header checks
- `sslyze==6.3.1`: TLS assessment
- `wafw00f==2.4.2`: WAF fingerprinting
- `wapiti3==3.3.0`: web application scanner, executable `wapiti`
- `mitmproxy==12.2.3`: proxy/manual traffic capture support
- `tldextract`, `dnspython`, `requests`, `beautifulsoup4`: helper libraries
- `fastapi==0.118.3` / `starlette==0.48.0`: lightweight route-introspection
  support used for OSS web/API target PoCs without installing full target
  runtimes
- `tqdm==4.67.3`: lightweight dependency needed to execute InvokeAI
  download-service proof paths with target code

Known Python caveats:

- `semgrep==1.163.0` is operational through the harness. The harness sets
  workspace-local `HOME`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `SEMGREP_SEND_METRICS=off`, and `SEMGREP_ENABLE_VERSION_CHECK=0` to avoid
  the prior macOS trust-store and home-directory write failures.
- `setuptools<81` is pinned because `dirsearch` imports legacy
  `pkg_resources`.
- `dnsrecon==0.10.1` is installed but currently not usable on Python 3.14
  because it imports removed `urllib.request.FancyURLopener`. Use `dnsx`,
  `subfinder`, and `amass` for operational DNS recon unless `dnsrecon` is
  moved to an older Python venv.
- `dirsearch` downgraded `charset-normalizer` to `2.0.12`; this venv is a
  tool environment, not an application runtime.
- Installing `fastapi==0.118.3` changed `starlette` from `1.0.0` to `0.48.0`.
  `sse-starlette==3.4.4` declares `starlette>=0.49.1`, so SSE-specific local
  testing should be done in a target-specific venv if needed. The VAPT harness
  route-introspection PoC path remains operational.

## System Tools

Installed with Homebrew:

- `amass 5.1.1`: external asset/subdomain discovery
- `coreutils 9.11`: provides GNU `timeout` via gnubin PATH
- `dalfox 2.13.0`: focused XSS testing
- `dnsx 1.2.3`: DNS probing
- `feroxbuster 2.13.1`: content discovery
- `ffuf 2.1.0`: fuzzing/content discovery
- `katana 1.6.1`: crawler
- `naabu 2.6.1`: port discovery
- `nikto 2.6.0`: web server checks
- `nmap 7.99`: network/service discovery
- `nuclei 3.8.0`: template-based checks
- `osv-scanner 2.3.8`: OSV dependency/advisory scanning
- `subfinder 2.14.0`: passive subdomain discovery
- `testssl.sh 3.2.3`: TLS checks
- `tlsx 1.2.2`: TLS probing
- `trufflehog 3.95.3`: secret detection

Workspace-local Go-installed tool:

- `.vapt-bin/httpx v1.9.0`: ProjectDiscovery HTTP probing and tech detection

Workspace-local downloaded tool:

- `.vapt-bin/codeql`: CodeQL CLI `2.25.5`, installed from the official
  `github/codeql-cli-binaries` release asset `codeql-osx64.zip`
- Install root: `.vapt-tools/codeql/codeql`
- Verified SHA-256:
  `1b3f785a8c8746668c5575bf6ffab4ec46e9207519e8aab82babb2a21beaf538`

Known system caveats:

- The global `httpx` on PATH is a broken Python CLI in this environment. Use
  `. ./vapt_env.sh` first, then `httpx`, or call `.vapt-bin/httpx` directly.
- Docker/Podman are not installed. Harness `sandbox-exec` uses the macOS
  `/usr/bin/sandbox-exec` fallback on this host, denying network access and
  limiting writes to the evidence directory unless explicit `:rw` mounts are
  supplied.
- ProjectDiscovery tools should be run with `HOME=$PWD/.vapt-home` or through
  `vapt_env.sh` to avoid sandbox write failures under
  `~/Library/Application Support`.
- For Cloudflare-fronted blackbox targets, broad `nmap`/`naabu` scans against
  edge IPs are low-signal and should not be the default.

## Verification Snapshot

Verified successfully:

- GNU `timeout` via coreutils
- `nmap`
- `nikto`
- `testssl.sh` with coreutils PATH
- `nuclei` with workspace HOME
- `ffuf`
- `feroxbuster`
- `subfinder` with workspace HOME
- `katana` with workspace HOME
- `naabu`
- `tlsx` with workspace HOME
- `dalfox`
- `trufflehog`
- `dnsx`
- `.vapt-bin/httpx`
- `wafw00f`
- `dirsearch`
- `pip-audit`
- `osv-scanner`
- `bandit`
- `detect-secrets`
- `semgrep`
- `sslyze`
- `codeql`

Harness wrapper availability snapshot from `tool-health --json` on
2026-05-25:

- Available: `semgrep`, `bandit`, `pip-audit`, `osv-scanner`, `trufflehog`,
  `sslyze`, `testssl.sh`, `nuclei`, `codeql`
- Semgrep version check now returns `1.163.0` through the harness environment.

Not verified as operational:

- `dnsrecon` under Python 3.14, due compatibility issue described above.
