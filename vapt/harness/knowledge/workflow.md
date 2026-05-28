# Candidate Workflow

Canonical state machine:

```text
candidate
  -> deduped
  -> promoted
  -> proved
  -> root_cause_recorded
  -> variant_searched
  -> patch_diffed
  -> report_ready
  -> submitted
  -> triaged | duplicate | n_a | resolved | paid
```

Transition preconditions:

- `candidate`: initial exploit thesis exists.
- `deduped`: `dedup.status` is checked and novelty is not `unchecked`.
- `promoted`: gate passes; novelty is not blocking; latest affected is
  confirmed; CWE and CVSS are valid.
- `proved`: `proof = passed` and raw proof evidence exists.
- `root_cause_recorded`: `root_cause` is non-empty and substantive.
- `variant_searched`: `variant_analysis` artifact exists or is explicitly
  scoped out in notes.
- `patch_diffed`: `patch_diff` artifact exists or missing refs are documented.
- `report_ready`: proof passed, gate passed, root cause recorded, variant search
  complete, negative controls recorded, CVSS/CWE valid, dedup checked.
- `submitted`: external submission ID is recorded.
- Terminal states: `triaged`, `duplicate`, `n_a`, `resolved`, `paid`.

Legacy run statuses may exist, but new automation should use canonical states
where possible.
