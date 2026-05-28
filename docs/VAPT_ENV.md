# VAPT Environment

Workspace-local Python environment:

```sh
python3 -m venv .venv-vapt
. .venv-vapt/bin/activate
python -m pip install --upgrade pip
python -m pip install -r vapt/env/requirements-vapt.txt
```

Preferred activation for day-to-day VAPT work:

```sh
. ./vapt_env.sh
```

See also:

- `VAPT_TOOLING_INVENTORY.md`
- `VAPT_TEST_PLAN.md`
- `../harness/README.md`
- `vapt/env/requirements-vapt.lock`

## Mini-MDASH Harness

The local harness lives at `vapt/harness/` and uses Python plus YAML support.
The current environment has suitable YAML support available. Use it for
source-assisted BB/VAPT runs:

```sh
.venv-vapt/bin/python vapt/harness/harness.py --help
```

The harness writes generated runs under:

```text
vapt/harness/runs/<target>/<run-id>/
```

Scanner wrappers added on 2026-05-18 and toolchain-expanded on 2026-05-25:

```sh
.venv-vapt/bin/python vapt/harness/harness.py tool-health --json
.venv-vapt/bin/python vapt/harness/harness.py scan-semgrep <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py scan-bandit <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py scan-pip-audit <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py scan-osv <run_dir>
.venv-vapt/bin/python vapt/harness/harness.py scan-trufflehog <run_dir>
```

`semgrep`, `bandit`, `pip-audit`, and `sslyze` are installed inside
`.venv-vapt`. `trufflehog`, `testssl.sh`, `nuclei`, and `osv-scanner` are
available through Homebrew. CodeQL CLI `2.25.5` is installed workspace-locally
under `.vapt-tools/codeql` and exposed as `.vapt-bin/codeql`.

Semgrep is operational through harness-managed environment variables for
workspace-local `HOME`, certificate bundle, disabled metrics, and disabled
version checks. Prefer `harness.py scan-semgrep` over invoking Semgrep directly.

## Target-Specific Bug Bounty Environments

These environments are separate from `.venv-vapt` to avoid contaminating the
blackbox toolchain with target dependency pins.

### DemoTarget

Path: `demo-target-release-v11.7.0`

Purpose: local source review and PoC validation for DemoTarget server BB work.

Version:

```text
DemoTarget v11.7.0
Commit a9e574a82633915f22071f0d7ca2b006f249ec2a
Go 1.26.0
```

Go analysis tools:

```text
~/go/bin/gosec
~/go/bin/govulncheck v1.3.0
```

DemoTarget test harness services installed 2026-05-16:

```text
PostgreSQL 17.10 via Homebrew
Redis 8.6.3 via Homebrew
```

Disposable service configuration used for local tests:

```text
PostgreSQL data dir: /private/tmp/mm-pgdata-demo-target-20260516
PostgreSQL listen: 127.0.0.1:5432
PostgreSQL roles: root, mmuser
Redis listen: 127.0.0.1:6379
```

DemoTarget Go commands require local module/cache overrides:

```sh
GOWORK="$PWD/demo-target-release-v11.7.0.go.work" \
GOCACHE=/private/tmp/go-build \
GOMODCACHE=/private/tmp/go-mod \
go test ./channels/api4 -run '^TestPatchCPAValues$/^websocket broadcasts value updates to unrelated users$' -count=1 -v
```

`demo-target-release-v11.7.0.go.work` maps `server` and `server/public` to the
local checkout so tests and analyzers use the release source consistently.

### demo-pyml

Path: `.venv-bounty-demo-pyml`

Purpose: local source review and PoC validation for `demo-pyml-dev/demo-pyml`.

Created: 2026-05-15

Python:

```text
Python 3.14.3
```

Installed target/dependencies:

```text
demo-pyml 0.15.dev0 editable from ./demo-pyml-review
numpy 2.4.4
scipy 1.17.1
scikit-learn 1.8.0
joblib 1.5.3
prettytable 3.17.0
PyYAML 6.0.3
pytest 9.0.3
pytest-cov 7.1.0
coverage 7.14.0
threadpoolctl 3.6.0
```

Release validation used `PYTHONPATH=.` from `./demo-pyml-release-v0.13.0` so the
same dependency environment could run against the latest public release source
without replacing the editable main install.

Reusable probe:

```sh
.venv-bounty-demo-pyml/bin/python vapt/pocs/demo-pyml/2026-05-15/probe_demo-pyml_controls.py
```

System tools installed with Homebrew:

```sh
amass
coreutils
dalfox
dnsx
feroxbuster
ffuf
katana
naabu
nmap
nikto
nuclei
subfinder
testssl.sh
tlsx
trufflehog
```

For `nuclei`, keep config/cache inside this workspace:

```sh
HOME="$PWD/.vapt-home" nuclei -version
HOME="$PWD/.vapt-home" nuclei -update-templates
```

Installed Python tools are intended for authorized defensive testing only.
Use low-impact profiles first, keep scope explicit, and avoid brute force or
destructive checks unless separately authorized.

Baseline deep-VA sequence for a single authorized host:

```sh
. .venv-vapt/bin/activate
shcheck.py https://example.com
sslyze --regular example.com
testssl.sh --fast --parallel 3 https://example.com
nmap -Pn -sV --top-ports 100 --version-light example.com
nikto -h https://example.com -Tuning x
HOME="$PWD/.vapt-home" nuclei -u https://example.com -severity low,medium,high,critical -rl 2
```

## Outside-In Blackbox Policy

When the assessment is external blackbox and no origin/VPN/internal access is
provided, treat CDN/WAF behavior as part of the public attack surface. Do not
try to infer or scan private origin infrastructure.

For Cloudflare-fronted targets, avoid broad service/version scans against the
edge IP by default. They are low-signal, may stall, and mostly assess
Cloudflare rather than the application origin. Prefer serial web-layer checks:

- HTTP/HTTPS redirects and cookies
- security headers
- TLS configuration
- exposed well-known files and framework paths
- safe scanner templates at low rate
- controlled crawler checks with hard time limits

Use the guarded runner so stalled tasks are terminated and logged:

```sh
RESOLVE_IP=104.26.10.219 STEP_TIMEOUT=180 ./vapt/scripts/vapt_blackbox_guarded.sh \
  https://aiboardroom.com/home.aspx \
  aiboardroom.com \
  vapt/evidence/aiboardroom.com/2026-05-15/aiboardroom-guarded
```

Each step writes:

- `<step>.out`
- `<step>.err`
- `<step>.status`
- `status.log`

Status `124` means the step timed out and was terminated.
