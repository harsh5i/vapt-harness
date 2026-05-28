# Prompt Injection With Downstream Impact

Thesis shape:

- Attacker controls model-visible content.
- The model can invoke tools, retrieve secrets, modify state, or influence a
  privileged downstream action.
- Prompt injection causes concrete data exfiltration, privilege escalation,
  file/network access, or unauthorized write.

Required proof:

- Benign content control.
- Malicious content with deterministic downstream effect.
- Tool/action logs proving the boundary crossing.
- No reliance on content-policy bypass alone.

Common sinks:

- Tool/function calls.
- Code interpreters.
- RAG retrieval persistence.
- Agent memory writes.
- Connectors with read/write permissions.
