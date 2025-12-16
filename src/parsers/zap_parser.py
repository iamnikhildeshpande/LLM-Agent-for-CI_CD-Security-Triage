import json
from defusedxml import ElementTree as ET
from utils import Finding, stable_fingerprint

def parse_zap(path):
    findings = []
    if path.suffix == ".json":
        data = json.loads(path.read_text())
        alerts = data.get("site", [{}])[0].get("alerts", [])
        for a in alerts:
            fp = stable_fingerprint("zap", a.get("pluginid"), a.get("url"))
            findings.append(Finding(
                source="zap",
                title=f"ZAP: {a.get('alert')}",
                description=a.get("desc"),
                severity=a.get("risk", "MEDIUM"),
                file_path=a.get("url"),
                rule_id=a.get("pluginid"),
                cwe=a.get("cweid"),
                cvss=None,
                fingerprint=fp,
                metadata={}
            ))
    else:
        tree = ET.parse(str(path))
        root = tree.getroot()
        for alert in root.findall(".//alertitem"):
            title = alert.findtext("alert")
            fp = stable_fingerprint("zap", alert.findtext("pluginid"), alert.findtext("uri"))
            findings.append(Finding(
                source="zap",
                title=f"ZAP: {title}",
                description=alert.findtext("desc"),
                severity=alert.findtext("riskdesc"),
                file_path=alert.findtext("uri"),
                rule_id=alert.findtext("pluginid"),
                cwe=alert.findtext("cweid"),
                cvss=None,
                fingerprint=fp,
                metadata={}
            ))
    return findings