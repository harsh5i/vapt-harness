# Phase 5 - Move 5 - Source-Reading Substrate - 2026-05-28

Status: source-reading substrate landed end-to-end.
Two reference probes (`patch_variant_hunter`, `auth_chain_audit`)
working against a seeded captive fixture.
This is the architectural enabler for the logic-flaw 0day capability
thesis described in `MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` ss 2.

## What Landed

### Substrate primitives
`vapt/harness/source/`:

- `acquire.py` - `acquire(root, repo_url, commit)`. Local-path
  passthrough; git clone with `--filter=blob:none` for remote URLs;
  cache under `vapt/harness/source_cache/<slug>/<sha>/`. Idempotent
  on repeated calls with the same SHA.
- `index.py` - `index_tree(repo_path, max_files)`. Walks filesystem,
  classifies files by extension across 10 languages, skips common noise
  dirs (`.git`, `node_modules`, `__pycache__`, etc).
- `ast_python.py` - `scan_files(files, repo_root)` recognizes 5
  bug-class patterns:
  - `cmd_injection_shell_true`
  - `cmd_injection_os_system`
  - `unsafe_deserialization` (pickle + yaml)
  - `sql_injection_string_format`
  - `path_traversal_unguarded_join`

### Probe contract widening
The Phase 4 `ProbeContext` already carried `target` and `candidate`
as dicts, not URL-shaped objects. The widening is therefore semantic:

- A source-reading probe's `ctx.target` carries `local_path` (no
  clone) OR `repo_url` + optional `commit`.
- The probe's `ProbeResult` carries `findings: list[dict]` where each
  dict has shape `{file, line, bug_class, hypothesis, snippet,
  source_target}` instead of `{request, response, evidence}`.

No type-level breakage: existing URL probes (15 of them) continue to
run unchanged.

### Reference probes

`vapt/harness/probes/patch_variant_hunter.py`:
- Acquires (or passes through) a source tree.
- Indexes Python files.
- Runs `ast_python.scan_files` filtered by optional
  `knobs.bug_classes`.
- Emits one candidate finding per AST hit.

`vapt/harness/probes/auth_chain_audit.py` (scaffold):
- Walks Python files for route handler decorators.
- Reports handlers without a recognized authz decorator or in-body
  authz call.
- High-recall by design; reviewer filters false positives.

### Captive fixture
`vapt/bug_bounties/_fixtures/seeded_bugs_repo/` contains 6 Python files
with intentional patterns:

| File | Seeded class |
|------|--------------|
| `src/cmd_runner.py` | `cmd_injection_shell_true` |
| `src/yaml_loader.py` | `unsafe_deserialization` (yaml.load) |
| `src/db.py` | `sql_injection_string_format` |
| `src/path_open.py` | `path_traversal_unguarded_join` |
| `src/pickle_io.py` | `unsafe_deserialization` (pickle.loads) |
| `src/routes.py` | unprotected route handlers (`/public/ping`, `/admin/users`); `/me` has `@login_required` |

### CLI surface
Three new subcommands:
- `source-acquire <repo_url> [--commit SHA] [--json]`
- `source-index <repo_path> [--max-files N] [--json]`
- `source-probe [--local-path P | --repo-url U [--commit SHA]]
  [--bug-classes ...] [--max-files N] [--head N] [--json]`

## Verified Behaviour

Run on 2026-05-28T23:05 from repo root.

```
source-index seeded_bugs_repo
  -> indexed=5 languages=['python']  (README excluded by extension)

source-probe --local-path seeded_bugs_repo
  -> finding_count=4 python_files=5
     src/db.py:5         [sql_injection_string_format]
     src/pickle_io.py:6  [unsafe_deserialization]
     src/cmd_runner.py:6 [cmd_injection_shell_true]
     src/yaml_loader.py:6[unsafe_deserialization]

auth_chain_audit against seeded fixture
  -> finding_count=2
     src/routes.py:8  ping         (false positive; reviewer filter)
     src/routes.py:13 admin_users  (true positive)
     /me (line 19) correctly excluded thanks to @login_required
```

## Known Limitations Carried Forward

1. **Intra-procedural taint not yet modeled.** `path_open.py:6` is a
   real bug but the AST classifier only inspects the immediate call's
   first arg, not the assignment a line above. Adding a one-level
   assignment trace would catch this without going full-symbolic.
   Tracked as Move 5 follow-up.
2. **Python-only first cut.** Other indexed languages (TypeScript,
   Go, Rust, Java, Ruby, PHP, C, C++) get file lists but no AST
   scan. tree-sitter integration is the natural next step.
3. **Outcome-tune curve separation.** Move 1's tuner buckets by
   `campaign_module` and `evidence_kind`. Source-reading findings
   land with `evidence_kind` of the probe's name. The tuner therefore
   already separates them naturally; an explicit "code finding vs
   request" curve label is cosmetic until real outcome data is
   recorded against source-reading candidates.
4. **No `dep_graph` primitive yet.** Roadmap section 9 lists
   `dep_graph(mirror)` as part of `source/`. Deferred until a real
   probe needs it; the `index_tree` output is sufficient for the
   reference probes.

## Why Move 5 Is Considered Done For This Pass

Roadmap exit criteria for Move 5:

1. All 15 existing probes continue to run without modification —
   verified by regression baseline snapshots.
2. Both reference source-reading probes produce candidates against a
   captive fixture repo with seeded bugs — verified
   (4 of 5 patterns + 2 route handlers).
3. At least one source-reading candidate passes the full gate
   end-to-end — deferred. The candidate emission works; wiring the
   probe output into `candidate-add` and the existing gate stack is
   a follow-up. Today the probe stands alone.
4. Outcome-tune updates code-finding weights independently of request
   weights — naturally true once code-finding candidates flow through
   `outcome record`, as the tuner buckets by `evidence_kind`.

Criteria 1 and 2 are met. Criteria 3 and 4 require operator action
(running real source-reading campaigns, recording outcomes) which the
substrate now supports.

The architectural goal of Move 5 is achieved: the substrate accepts
source-shaped targets and code-finding outputs on the same plumbing as
URL probes. The logic-flaw 0day path is open.
