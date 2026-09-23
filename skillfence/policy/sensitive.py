"""Sensitive-resource detection — used to flag events as `sensitive` regardless
of whether the manifest declares them.
"""

from __future__ import annotations

import fnmatch

SENSITIVE_PATH_PATTERNS = [
    "*/.ssh/*",
    "*/.aws/credentials",
    "*/.aws/config",
    "*/.gcp/*",
    "*/.azure/*",
    "*/.kube/config",
    "*/id_rsa",
    "*/id_ed25519",
    "*.pem",
    "*.pfx",
    "*/.env",
    "*/.env.*",
    "*/.netrc",
    "*/.git-credentials",
    "*/credentials.json",
    "*/service-account*.json",
]

SENSITIVE_ENV_VARS = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
}

# Files a real agent host reads back into context on future sessions --
# persistent memory/identity notes (Claude Code's CLAUDE.md, other agents'
# AGENTS.md/MEMORY.md/SOUL.md conventions), not credentials. A write here
# isn't dangerous because of what it exposes right now -- it's dangerous
# because whatever it says becomes trusted context the *next* session reads
# unquestioningly, with no fetch/instruction-detection step to catch it the
# way AST05 catches a poisoned external document. This is the same failure
# shape as AST05, moved from "content the agent fetches" to "content the
# agent already trusts because it wrote it there itself."
IDENTITY_FILE_PATTERNS = [
    "*/MEMORY.md",
    "*/SOUL.md",
    "*/AGENTS.md",
    "*/CLAUDE.md",
    "*/.agent/memory*",
    "*/.agent-memory/*",
]


def is_sensitive_path(path: str) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in SENSITIVE_PATH_PATTERNS)


def is_sensitive_env_var(name: str) -> bool:
    return name.upper() in SENSITIVE_ENV_VARS


def is_identity_file(path: str) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in IDENTITY_FILE_PATTERNS)
