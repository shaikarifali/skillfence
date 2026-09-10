"""Ed25519 keypair generation, and signing/verifying a file's contents.

Deliberately whole-file signing (one signature over the file's raw bytes),
not per-record signing — simpler to reason about ("is this exact file, as
a whole, unmodified since it was signed"), and it never has to know
anything about the internal shape of what it's signing, so it works
identically on a findings.jsonl, an events.jsonl, or a rendered
Markdown/JSON report.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_PRIVATE_KEY_PATH = Path(".skillfence/audit_signing_key")
DEFAULT_PUBLIC_KEY_PATH = Path(".skillfence/audit_signing_key.pub")

SIG_FORMAT_VERSION = 1
SIG_ALGORITHM = "ed25519"


def default_sig_path(signed_file: Path) -> Path:
    return signed_file.with_suffix(signed_file.suffix + ".sig.json")


def generate_keypair(
    *, private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH, public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH
) -> None:
    """Generates a new local Ed25519 keypair. The private key never leaves
    disk in plaintext PEM form -- this is for local audit-trail integrity,
    not custody of a high-value secret; back it up like any other local
    credential you don't want to lose (losing it means old evidence can no
    longer be *re-signed*, though already-signed files remain verifiable
    against the public key you already handed out).
    """
    if private_key_path.exists():
        raise FileExistsError(f"{private_key_path} already exists — refusing to overwrite an existing signing key")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o600)

    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(
        public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def load_private_key(path: Path = DEFAULT_PRIVATE_KEY_PATH) -> Ed25519PrivateKey:
    if not path.exists():
        raise FileNotFoundError(f"no signing key at {path} — run `skillfence audit keygen` first")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path = DEFAULT_PUBLIC_KEY_PATH) -> Ed25519PublicKey:
    if not path.exists():
        raise FileNotFoundError(f"no public key at {path}")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


@dataclass
class SignatureRecord:
    file: str
    algorithm: str
    signature_b64: str
    signed_at: str
    format_version: int = SIG_FORMAT_VERSION

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "algorithm": self.algorithm,
            "signature_b64": self.signature_b64,
            "signed_at": self.signed_at,
            "format_version": self.format_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SignatureRecord":
        return cls(
            file=data["file"],
            algorithm=data["algorithm"],
            signature_b64=data["signature_b64"],
            signed_at=data["signed_at"],
            format_version=data.get("format_version", 1),
        )


def sign_file(target: Path, *, private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH, sig_path: Optional[Path] = None) -> Path:
    """Signs `target`'s current bytes, writing a sidecar `.sig.json`.
    Returns the sidecar's path.
    """
    private_key = load_private_key(private_key_path)
    content = target.read_bytes()
    signature = private_key.sign(content)

    record = SignatureRecord(
        file=target.name,
        algorithm=SIG_ALGORITHM,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        signed_at=datetime.now(timezone.utc).isoformat(),
    )
    sig_path = sig_path or default_sig_path(target)
    sig_path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
    return sig_path


@dataclass
class VerificationResult:
    valid: bool
    reason: str


def verify_file(
    target: Path, *, public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH, sig_path: Optional[Path] = None
) -> VerificationResult:
    """Re-hashes `target`'s current bytes and checks them against the
    signature recorded in its sidecar. `valid=False` means either the
    target file changed since it was signed, or the signature/public key
    don't match -- either way, don't trust the file's contents.
    """
    sig_path = sig_path or default_sig_path(target)
    if not sig_path.exists():
        return VerificationResult(valid=False, reason=f"no signature file at {sig_path}")
    if not target.exists():
        return VerificationResult(valid=False, reason=f"signed file {target} does not exist")

    record = SignatureRecord.from_dict(json.loads(sig_path.read_text(encoding="utf-8")))
    if record.algorithm != SIG_ALGORITHM:
        return VerificationResult(valid=False, reason=f"unsupported algorithm {record.algorithm!r}")
    if record.file != target.name:
        return VerificationResult(
            valid=False, reason=f"signature was made for {record.file!r}, not {target.name!r} — wrong sidecar?"
        )

    try:
        public_key = load_public_key(public_key_path)
    except (FileNotFoundError, ValueError) as exc:
        return VerificationResult(valid=False, reason=str(exc))

    signature = base64.b64decode(record.signature_b64)
    content = target.read_bytes()
    try:
        public_key.verify(signature, content)
    except InvalidSignature:
        return VerificationResult(valid=False, reason="signature does not match this file's current contents — tampered or resigned elsewhere")
    return VerificationResult(valid=True, reason=f"signed {record.signed_at}, verified against {public_key_path}")
