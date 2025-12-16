import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Optional, List


class ServiceNowClient:
    """
    ServiceNow client for creating and updating incidents based on CI/CD findings.
    """

    def __init__(self, instance_url: str, username: str, password: str):
        """
        Initialize the ServiceNow client.

        Args:
            instance_url: Base URL of the ServiceNow instance (e.g., https://yourinstance.service-now.com)
            username: ServiceNow username
            password: ServiceNow password
        """
        self.base_url = instance_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def _incident_url(self) -> str:
        return f"{self.base_url}/api/now/table/incident"

    def search_incident_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        """
        Search for an existing incident by fingerprint.

        Args:
            fingerprint: Unique fingerprint string for the finding.

        Returns:
            sys_id of the incident if found, else None.
        """
        params = {
            "sysparm_query": f"u_fingerprint={fingerprint}^active=true",
            "sysparm_limit": "1"
        }
        response = self.session.get(self._incident_url(), params=params)
        response.raise_for_status()
        results = response.json().get("result", [])
        return results[0]["sys_id"] if results else None

    def create_incident(self, item: Dict[str, Any], ci_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new incident in ServiceNow.

        Args:
            item: Finding dictionary with keys like title, description, severity, fingerprint.
            ci_context: Context dictionary with build_id, artifacts_url, assignment_group, short_app_name.

        Returns:
            Dictionary with action and sys_id.
        """
        priority_map = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3", "LOW": "4"}

        payload = {
            "short_description": f"[{ci_context.get('short_app_name', 'App')}] {item['title']}",
            "description": (
                f"{item['description']}\n\n"
                f"Source: {item['source']}\n"
                f"Fingerprint: {item['fingerprint']}\n"
                f"Build: {ci_context.get('build_id')}\n"
                f"Artifacts: {ci_context.get('artifacts_url')}"
            ),
            "u_fingerprint": item["fingerprint"],
            "priority": priority_map.get(item["severity"], "3"),
            "assignment_group": ci_context.get("assignment_group"),
            "u_ci_pipeline": ci_context.get("build_id"),
            "category": "Security",
            "subcategory": "Application",
            "state": "1"  # New
        }

        response = self.session.post(self._incident_url(), json=payload)
        response.raise_for_status()
        result = response.json().get("result", {})
        return {"action": "created", "sys_id": result.get("sys_id")}

    def update_incident(self, sys_id: str, build_id: str) -> Dict[str, Any]:
        """
        Update an existing incident with new work notes.

        Args:
            sys_id: ServiceNow incident sys_id.
            build_id: CI/CD build identifier.

        Returns:
            Dictionary with action and sys_id.
        """
        update_url = f"{self._incident_url()}/{sys_id}"
        payload = {"work_notes": f"Finding re-triggered in build {build_id} - still present."}
        response = self.session.patch(update_url, json=payload)
        response.raise_for_status()
        return {"action": "updated", "sys_id": sys_id}

    def create_or_update_incident(self, item: Dict[str, Any], ci_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update an incident based on fingerprint.

        Args:
            item: Finding dictionary.
            ci_context: CI/CD context dictionary.

        Returns:
            Dictionary with action and sys_id.
        """
        existing_sys_id = self.search_incident_by_fingerprint(item["fingerprint"])
        if existing_sys_id:
            return self.update_incident(existing_sys_id, ci_context.get("build_id"))
        else:
            return self.create_incident(item, ci_context)

    def push_findings(self, findings: List[Dict[str, Any]], ci_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Push multiple findings to ServiceNow.

        Args:
            findings: List of finding dictionaries.
            ci_context: CI/CD context dictionary.

        Returns:
            List of results with action and sys_id.
        """
        results = []
        for f in findings:
            try:
                res = self.create_or_update_incident(f, ci_context)
                results.append({"fingerprint": f["fingerprint"], **res})
            except requests.HTTPError as e:
                results.append({"fingerprint": f["fingerprint"], "action": "error", "error": str(e)})
        return results