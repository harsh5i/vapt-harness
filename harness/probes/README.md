# Probe Library

Reusable probes are class-specific validation checks for authorized local or
captive evidence. They do not exploit targets by themselves. They check whether
a candidate has the proof shape expected for a reportable finding.

Each probe implements `Probe.run(ctx)` and returns structured fields:

- `passed`: whether the candidate evidence shape is complete.
- `missing`: concrete gaps that block report readiness.
- `recommended_next`: the next evidence collection step.

Run the captive regression set:

```sh
.venv-vapt/bin/python vapt/harness/harness.py probes-test
```

Add new probes with:

```sh
.venv-vapt/bin/python vapt/harness/harness.py new-probe <name> --vuln-class <class>
```
