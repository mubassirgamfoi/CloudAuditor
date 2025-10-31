from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class KubernetesChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        cs = "CIS DigitalOcean Services Benchmark v1.0.0"
        return [
            self.create_finding(
                check_id="do_svc_3.1",
                title="Ensure Log Forwarding is Enabled (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:k8s:log-forwarding",
                description="DOKS cluster does not have log forwarding destination configured.",
                recommendation="Configure Event log forwarding to a Managed OpenSearch destination.",
                command="(UI) Kubernetes → Cluster → Settings → Event log forwarding",
                evidence={"destinations": []},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_3.2",
                title="Ensure an Upgrade Window is Defined (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:k8s:upgrade-window",
                description="Automatic minor patch upgrade window is not defined.",
                recommendation="Enable automatic minor version patches with a defined 4-hour window.",
                command="doctl kubernetes cluster get <id|name> --output json",
                evidence={"autoUpgrade": False, "maintenanceWindow": None},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_3.3",
                title="Ensure High Availability Control Plane is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:k8s:ha-control-plane",
                description="High availability control plane is not enabled.",
                recommendation="Enable HA control plane for increased resiliency and SLA.",
                command="doctl kubernetes cluster update <id|name> --ha",
                evidence={"ha": False},
                compliance_standard=cs,
            ),
        ]


