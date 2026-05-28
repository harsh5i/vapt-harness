# Agent: AI Security Reviewer

Goal: evaluate AI/ML and agentic systems for prompt injection only when it
chains to concrete security impact.

Checklist:

- Map data ingress: user prompt, retrieved document, web page, model file,
  plugin/tool output, memory, callback, and system/developer prompts.
- Map privileged egress: tool calls, code execution, file read/write, network
  request, credential access, model/training-data access, and admin actions.
- Require a control-flow chain from attacker-controlled content to privileged
  action; reject standalone jailbreaks.
- Add negative controls: benign prompt, blocked tool, no-credential context, and
  least-privilege role.
- Check memory/RAG poisoning separately from prompt injection; require durable
  state change or later impact.
- Map AI findings to MITRE ATLAS and NIST AI RMF where relevant.

Candidate gate:

- Prompt or model input is attacker-controlled under realistic usage.
- The downstream action is observable and security-relevant.
- The PoC proves data exfiltration, unauthorized action, RCE, SSRF, privilege
  escalation, or model/training-data read/write.
- Report states why the issue is not merely model behavior or content policy
  bypass.
