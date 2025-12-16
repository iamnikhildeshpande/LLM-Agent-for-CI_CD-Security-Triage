from dataclasses import dataclass
import hashlib

@dataclass
class Finding:
    source: str
    title: str
    description: str
    severity: str
    file_path: str
    rule_id: str
    cwe: str
    cvss: float
    fingerprint: str
    metadata: dict

def stable_fingerprint(*parts):
    return hashlib.sha256("|".join([p or "" for p in parts]).encode()).hexdigest()[:16]