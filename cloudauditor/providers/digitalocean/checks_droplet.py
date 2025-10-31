from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class DropletChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        cs = "CIS DigitalOcean Services Benchmark v1.0.0"
        return [
            self.create_finding(
                check_id="do_svc_2.1",
                title="Ensure Backups are Enabled (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean/droplet/backups",
                description="Droplet does not have automated backups enabled.",
                recommendation="Enable automated backups (daily/weekly) with a defined backup window.",
                command="doctl compute droplet-action enable-backups <droplet-id> --backup-policy-plan weekly --backup-policy-weekday SUN --backup-policy-hour 4",
                evidence={"backupsEnabled": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.2",
                title="Ensure a Firewall is Created (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean/firewall/present",
                description="No DigitalOcean Cloud Firewall defined for the project.",
                recommendation="Create a Cloud Firewall with least-privilege inbound/outbound rules.",
                command="doctl compute firewall create --name example --inbound-rules 'protocol:tcp,ports:22,address:10.0.0.0/8' --outbound-rules 'protocol:tcp,ports:80,address:0.0.0.0/0'",
                evidence={"firewalls": []},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.3",
                title="Ensure the Droplet is Connected to a Firewall (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean/droplet/firewall-association",
                description="Droplet is not associated with any Cloud Firewall.",
                recommendation="Attach Droplet to an existing Cloud Firewall or tag for policy application.",
                command="doctl compute firewall add-droplets <firewall-id> --droplet-ids <droplet-id>",
                evidence={"dropletId": 12345, "attachedFirewalls": []},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.4",
                title="Ensure Operating System on Droplet is Upgraded (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean/droplet/os-upgrade",
                description="Droplet OS version is nearing end-of-life.",
                recommendation="Plan and execute an upgrade to a supported OS release.",
                command="lsb_release -a | cat /etc/os-release",
                evidence={"distro": "Ubuntu", "version": "20.04"},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.5",
                title="Ensure Operating System is Updated (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean/droplet/os-updates",
                description="Pending OS security updates detected.",
                recommendation="Apply latest security updates (e.g., apt update && apt upgrade).",
                command="apt update && apt list --upgradable",
                evidence={"pendingUpdates": 12},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.6",
                title="Ensure auditd is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean/droplet/auditd",
                description="auditd is not enabled or running.",
                recommendation="Install, enable, and configure auditd with appropriate rules and rotation.",
                command="systemctl is-enabled auditd && systemctl is-active auditd",
                evidence={"enabled": False, "active": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.7",
                title="Ensure SSH Keys are Used to Authenticate (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean/droplet/ssh-key-auth",
                description="Password authentication is enabled for SSH.",
                recommendation="Require SSH key authentication and disable password authentication in sshd_config.",
                command="grep '^PasswordAuthentication' /etc/ssh/sshd_config",
                evidence={"PasswordAuthentication": "yes"},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_2.8",
                title="Ensure Unused SSH Keys are Deleted (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean/droplet/ssh-keys-unused",
                description="Stale SSH keys detected in account or on Droplet.",
                recommendation="Remove unused SSH keys from account and authorized_keys on Droplets.",
                command="doctl compute ssh-key list; grep -n 'ssh-' /home/*/.ssh/authorized_keys",
                evidence={"staleKeys": ["old-ci-key"]},
                compliance_standard=cs,
            ),
        ]


