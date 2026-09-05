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


def is_sensitive_path(path: str) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in SENSITIVE_PATH_PATTERNS)


def is_sensitive_env_var(name: str) -> bool:
    return name.upper() in SENSITIVE_ENV_VARS
