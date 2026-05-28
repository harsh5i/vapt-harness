# RAG Poisoning Durability

Reportable shape:

- Attacker controls content that enters a retrieval index.
- Poisoned content persists beyond one transient prompt.
- Retrieval returns the poisoned content in a later victim workflow.
- The poisoned retrieval causes concrete downstream impact, such as tool use,
  file read/write, credential exposure, or privilege boundary crossing.

Minimum evidence:

- Clean-index negative control.
- Poison ingestion step.
- Retrieval hit evidence after persistence/reload/reindex.
- Downstream unauthorized effect.
