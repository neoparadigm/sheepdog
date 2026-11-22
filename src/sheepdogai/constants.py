"""Single place for every name and pinned version that may change.

The project name is undecided. ``PACKAGE_NAME`` and ``CLI_NAME`` are the only places
the user-facing names appear in code, so a rename is a one-line change here plus the
``pyproject.toml`` entry point.
"""

from __future__ import annotations

__version__ = "0.1.5"

PACKAGE_NAME = "sheepdogai"
CLI_NAME = "sheepdogai"
CONFIG_FILE = "sheepdogai.yaml"
STATE_DIR = ".sheepdogai"
SCHEMA_VERSION = "1"

# Placeholder namespace; replace with a stable URL once the project has one.
ONTOLOGY_NS = "https://example.org/sheepdogai#"

# OpenTelemetry gen_ai semantic conventions are in Development stability.
# Only attributes checked against this version are mapped.
OTEL_GENAI_SEMCONV_VERSION = "1.37.0"
