import json, re
from openai import OpenAI
from utils import Finding

SYSTEM_PROMPT = """You are a CI/CD security triage assistant.
Normalize severity, deduplicate findings, and output JSON with only HIGH/CRITICAL issues."""

def llm_triage(findings, api_key, model="gpt-4o-mini"):
    client = OpenAI(api_key=api_key)
    payload = {"findings": [f.__dict__ for f in findings]}
    resp = client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":json.dumps(payload)}
        ]
    )
    content = resp.choices[0].message.content
    m = re.search(r"\{[\s\S]*\}", content)
    return json.loads(m.group(0)) if m else {}