from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class SecurityHistoryChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        return [
            self.create_finding(
                check_id="do_5.1",
                title="Ensure Security History is Reviewed Regularly (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:team:security-history",
                description="Security history review cadence is not documented or recent reviews are missing.",
                recommendation="Review Security History regularly and document cadence.",
                command="(UI) Control Panel → Settings → Security",
                evidence={"lastReview": None},
            ),
        ]


