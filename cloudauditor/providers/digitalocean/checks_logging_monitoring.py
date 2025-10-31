from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class LoggingMonitoringChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        cs = "CIS DigitalOcean Services Benchmark v1.0.0"
        return [
            self.create_finding(
                check_id="do_svc_4.1",
                title="Ensure Security History is Monitored (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:account:security-history",
                description="Security history review process is not documented/monitored.",
                recommendation="Review Security History regularly via Control Panel → Settings → Security.",
                command="(UI) Settings → Security → Security History",
                evidence={"lastReviewed": None},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_4.2",
                title="Ensure Resource Monitoring is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean/droplet/monitoring",
                description="Droplet does not have the DigitalOcean metrics agent installed.",
                recommendation="Enable Monitoring during creation or install the metrics agent manually.",
                command="doctl compute droplet get <id|name> --output json (monitoring) / install-agent script",
                evidence={"monitoringEnabled": False},
                compliance_standard=cs,
            ),
        ]


