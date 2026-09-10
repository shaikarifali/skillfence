"""Signed evidence — tamper-evident audit artifacts.

SkillFence's whole pitch is "explainable, auditable security decisions."
An audit trail that anyone with filesystem access can silently edit after
the fact undercuts that pitch. This module signs an evidence file (a
findings.jsonl, an events.jsonl, a rendered report) with a local Ed25519
keypair, producing a small sidecar `.sig.json` that anyone holding the
*public* key — not the private one — can use to verify the file is
byte-for-byte what was signed. Asymmetric by design: you can hand a
reviewer your public key and an evidence bundle without ever exposing the
private key that produced it.

This is deliberately not a PKI, a registry, or a publisher-identity
system — those are real, larger ideas that belong on the Roadmap, not
bundled into a local audit-integrity check. This module answers one
question only: "has this specific file changed since I signed it?"
"""
