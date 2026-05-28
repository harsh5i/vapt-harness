# Model Card Local File Read

Reportable shape:

- Attacker controls model-card metadata, Markdown, YAML, or template input.
- Rendering, publishing, or validation expands that input into a local file read.
- The read crosses a trust boundary and exposes local secrets, model artifacts,
  training data, or other sensitive files.

Minimum evidence:

- Benign model-card render.
- Malicious model-card render.
- Exact file-read sink and path resolution behavior.
- Denied or missing-file negative control.
