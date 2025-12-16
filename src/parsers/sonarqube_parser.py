import json
from utils import Finding, stable_fingerprint

def parse_sonarqube(json_path):
    findings = []
    data = json.loads(json_path.read_text())
    for issue in data.get("issues", []):
        if issue.get("type") not in ("VULNERABILITY", "SECURITY_HOTSPOT"):
            continue
        fp = stable_fingerprint("sonar", issue.get("rule"), issue.get("component"))
        findings.append(Finding(
            source="sonarqube",
            title=f"Sonar {issue.get('type')} [{issue.get('rule')}]",
            description=issue.get("message"),
            severity=issue.get("severity", "MEDIUM"),
            file_path=issue.get("component"),
            rule_id=issue.get("rule"),
            cwe=None,
            cvss=None,
            fingerprint=fp,
            metadata={}
        ))
    return findings