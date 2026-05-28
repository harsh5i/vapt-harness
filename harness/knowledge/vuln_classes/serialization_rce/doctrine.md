# Serialization RCE

Thesis shape:

- Attacker controls a serialized model, archive, manifest, or metadata file.
- Loader claims to be safe or has a trust/allowlist mechanism.
- A bypass reaches object construction, code execution, file write, file read, or
  another concrete security primitive.

Required proof:

- Latest version and exact dependency versions.
- Benign load control.
- Malicious load path with deterministic impact.
- Demonstration that the trust mechanism was bypassed, not merely that loading
  untrusted files is risky.

Common sinks:

- `pickle`, `dill`, `joblib`, `cloudpickle`, `yaml.load`.
- Object reconstruction dispatchers.
- Custom archive loaders.
- Type allowlist validators.
- Numpy/scipy dtype and object-array reconstruction paths.
