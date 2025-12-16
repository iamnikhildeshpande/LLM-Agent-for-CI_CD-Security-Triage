from defusedxml import ElementTree as ET
from utils import Finding, stable_fingerprint

def parse_junit(xml_path):
    findings = []
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    for tc in root.findall(".//testcase"):
        name = tc.attrib.get("name")
        classname = tc.attrib.get("classname")
        for tag in ("failure", "error"):
            node = tc.find(tag)
            if node is not None:
                msg = node.attrib.get("message", "")
                fp = stable_fingerprint("junit", classname, name, tag, msg)
                findings.append(Finding(
                    source="junit",
                    title=f"JUnit {tag}: {classname}.{name}",
                    description=msg,
                    severity="HIGH",
                    file_path=classname,
                    rule_id=None,
                    cwe=None,
                    cvss=None,
                    fingerprint=fp,
                    metadata={"tag": tag}
                ))
    return findings