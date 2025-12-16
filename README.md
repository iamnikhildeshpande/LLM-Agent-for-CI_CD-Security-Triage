# LLM CI/CD Security Agent 

This project provides a Python-based agent that:
- Crawls CI/CD artifacts (JUnit test reports, SonarQube SAST, OWASP ZAP vulnerability scans).
- Uses OpenAI Chat Completions to triage findings.
- Surfaces **HIGH** and **CRITICAL** issues into ServiceNow for teams to action before production rollout.

## Features
- Parsers for JUnit XML, SonarQube JSON, and ZAP XML/JSON.
- LLM-powered severity normalization and deduplication.
- ServiceNow integration with idempotency (fingerprint-based).
- Jupyter notebook demo for experimentation.

## Project Structure
See [src/](src/) for code, [tests/](tests/) for unit tests, and [notebooks/](notebooks/) for demo usage.

## Setup

1. Clone the repo:
   ```bash
   git clone <URL of the repo>
   cd llm-ci-security-agent

2. Install dependencies:
pip install -r requirements.txt

3. Configure environment variables:

OPENAI_API_KEY=your_openai_key
OPENAI_MODEL=gpt-4o-mini
SERVICENOW_INSTANCE=https://yourinstance.service-now.com
SERVICENOW_USER=your_user
SERVICENOW_PASSWORD=your_password

4. Run Orchestrator:

python src/main.py
