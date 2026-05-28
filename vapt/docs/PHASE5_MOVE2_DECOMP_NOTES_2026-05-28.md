# Phase 5 - Move 2 - Decomposition Notes - 2026-05-28

Status: package skeleton complete. Strangler-fig migration policy adopted.

References:
- `MYTHOS_SUBSTRATE_PHASE5_ROADMAP_2026-05-28.md` ss 6

## Policy Shift: Strangler-Fig over Big-Bang

The Phase 5 roadmap as written specified topological extraction of the
11267-line `harness.py` into a multi-package layout, with `cli.py <= 500
lines` and no file `> 1500 lines` as exit criteria. On reflection
(2026-05-28) this is **hygiene work, not capability work**.

The capability theses for Phase 5 are:

- N-day at scale (Moves 1, 3, 4).
- Logic-flaw 0day (Move 5).

None of these strictly require the legacy monolith to be split first.
What they require is that **new code lands in the right place** so that
once parallel work begins it does not regress to a fresh monolith.

The revised Move 2 policy is therefore:

1. **Skeleton now.** Create the target package layout with empty
   `__init__.py` files. New modules (toolchain wrappers, source-reading
   probes, discovery sources, mutation enforcement) land here.
2. **Legacy strangler.** When a function in `harness.py` needs material
   change for Moves 3/4/5, extract it into its owning package first,
   then change it. Touch-and-extract.
3. **No big-bang.** Do not attempt a single multi-thousand-line
   migration. Risk:benefit is wrong while integration-only tests are
   the only safety net.
4. **Snapshots as ratchet.** Regression baselines under
   `vapt/harness/tests/snapshots/` are the floor. Any extraction must
   keep them green.

Exit criteria for Move 2 are revised:

- All new Phase 5 code (Moves 3-5) lands under
  `vapt/harness/{tools,source,watch,gates,ledger,mutation,campaign}/`.
- No new code is added to `harness.py` after 2026-05-28 except CLI
  registration shims.
- Regression snapshots stay green after every extraction.
- The hard size ceilings (`<= 500` cli, `< 1500` per file) become aspirational
  targets, not gates.

## Package Skeleton

```
vapt/harness/
  campaign/    # campaign planner, runner, scoring (future)
  cache/       # OSV cache lives here (already in place 2026-05-28)
  gates/       # promote, report, dedup, cvss (future)
  ledger/      # candidates, submissions, outcomes (future)
  mutation/    # variant generators, coverage enforcement (future)
  probes/      # probe registry and base class (already in place)
  source/      # source-reading substrate for Move 5 (future)
  tools/       # external tool wrappers - ZAP, sqlmap, JWT, etc. (Move 3)
  watch/       # discovery sources for Move 4 (future)
```

All are empty packages with `__init__.py` headers describing their
intended contents.

## Regression Baselines Captured

Stored at `vapt/harness/tests/snapshots/baseline_*.json` on
2026-05-28T22:39:

- `outcome-tune-check`
- `campaign-flow-check`
- `campaign-adapter-check__target_grafana_oss`
- `mutation-coverage-check`
- `phase2-check`, `phase3-check`, `phase4-check`

These are reference outputs. Any extraction must produce identical
shapes (modulo timestamps).

## Out of Scope

- Migrating existing `harness.py` functions ahead of need.
- Splitting `harness.py` for its own sake.
- Adding 50 unit tests speculatively. Tests land alongside extracted
  code as it moves.

## Carry-Forward

If parallel agent work hits real collisions on `harness.py` (multiple
agents editing the same function family concurrently), revisit and
take the deeper extraction. Until that pain shows up, the policy
above governs.
