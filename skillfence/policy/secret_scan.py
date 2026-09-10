"""Content-based secret detection — the gap `sensitive.py` alone can't
close. `is_sensitive_path()` only asks whether a *name* looks sensitive
(`~/.aws/credentials`); it says nothing about a plainly-named file
(`notes.txt`, a tool's JSON response) that happens to have a live
credential pasted inside it. This is the single most cited real-world
Agentic Skill failure mode across public research (Snyk's Feb 2026
ToxicSkills audit: 280+ skills leaking credentials): a skill's *declared*
access looks fine, its *path* looks fine, and the secret still leaves
through the content itself.

Deliberately never returns the matched substring, only which *kind* of
secret pattern fired — a security tool's own findings/audit log must not
become a second place the leaked credential now lives in plaintext.
"""

from __future__ import annotations

import re

# (label, pattern) -- ordered roughly by how specific/high-confidence the
# match is. Specific vendor-prefixed formats first (near-zero false
# positive rate); the generic assignment pattern last (broader, catches
# what the specific ones miss, at the cost of being the one most likely to
# also flag a genuinely benign "password: changeme" placeholder -- still
# worth surfacing, since a human reviewing a HIGH finding costs far less
# than a leaked credential nobody caught).
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key (assignment)", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("GitHub Personal Access Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b")),
    ("Slack Webhook URL", re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    ("Stripe Secret Key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private Key Material", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT-Shaped Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("npm Auth Token", re.compile(r"//registry\.npmjs\.org/:_authToken=\S+")),
    (
        "Generic secret-like assignment",
        # Any 16+ non-quote characters between quotes -- real secret values
        # routinely include punctuation (!, @, #, ...) that a narrower
        # base64/hex-only character class would silently miss.
        re.compile(r"(?i)\b(password|secret|token|api[_-]?key)\b\s*[:=]\s*['\"][^'\"]{16,}['\"]"),
    ),
]


def scan_for_secrets(content: str) -> list[str]:
    """Returns the deduplicated list of secret-pattern *labels* found in
    `content` — never the matched text itself. Empty list means clean.
    """
    if not content:
        return []
    found: list[str] = []
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(content) and label not in found:
            found.append(label)
    return found
