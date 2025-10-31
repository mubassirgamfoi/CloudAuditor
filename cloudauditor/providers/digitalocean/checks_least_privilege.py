from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class LeastPrivilegeChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        return [
            self.create_finding(
                check_id="do_4.1",
                title="Ensure Role-Based Access Controls are Implemented (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="digitalocean:team:rbac",
                description="Team roles require review to enforce least privilege.",
                recommendation="Use predefined roles (Owner, Member, Biller, Modifier, Billing viewer, Resource viewer) and review assignments.",
                command="(UI) Control Panel → Settings → Team → Team Members",
                evidence={"members": [{"email": "dev@example.com", "role": "Owner"}]},
            ),
        ]


