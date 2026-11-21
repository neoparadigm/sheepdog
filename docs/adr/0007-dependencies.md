# 0007. Dependencies

Status: accepted

Core runtime dependencies are two:

* **pydantic v2**: frozen, validated, versioned event and config schemas with precise error
  locations. Writing and testing that by hand would be larger and less safe.
* **PyYAML**: rules files. Loaded with a `SafeLoader` subclass that rejects duplicate keys; never
  `yaml.load` with an unsafe loader (a test greps for it).

Optional extras: `otel` (opentelemetry-api, export is opt-in), `rdf` (rdflib, pyshacl: ontology
validation), `dev` (pytest, hypothesis, pytest-cov, mypy, ruff, plus the rdf extra for tests).
The build backend `hatchling` is pinned. Everything is locked in `uv.lock` and installed with hash
checking. We do not use: an HTTP client (no network in core), a shell-parsing library (the
normaliser is purpose-built and fuzzed; a real shell parser would not model what the agent CLI
runs either), or an ML library.
