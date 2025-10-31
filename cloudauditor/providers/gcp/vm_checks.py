"""
CIS Google Cloud Platform Foundation Benchmark - Virtual Machines Checks (Section 4)
Virtual machine security configuration checks
"""

from typing import Dict, Any, List
from cloudauditor.providers.gcp.base_checker import BaseGCPChecker


class VMChecker(BaseGCPChecker):
    """Checker for virtual machine security - CIS Google Cloud Platform Foundation Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all virtual machine checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_default_service_account())
            findings.extend(self.check_project_wide_ssh_keys())
            findings.extend(self.check_os_login())
            findings.extend(self.check_serial_port_access())
            findings.extend(self.check_ip_forwarding())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.ERROR",
                    title="Error Running Virtual Machine Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="gcp:vm",
                    description=f"Failed to run virtual machine checks: {str(e)}",
                    recommendation="Verify GCP permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def check_default_service_account(self) -> List[Dict[str, Any]]:
        """
        4.1: Ensure that instances are not configured to use the default service account
        Level: 1 | Type: Manual | HIGH
        """
        findings = []
        try:
            # This would check actual instances in real implementation
            # For now, return mock findings
            pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.1",
                    title="Unable to Check Default Service Account Usage",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="gcp:vm:instances",
                    description=f"Could not verify default service account usage: {str(e)}",
                    recommendation="Verify Compute Engine permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def check_project_wide_ssh_keys(self) -> List[Dict[str, Any]]:
        """
        4.2: Ensure that project-wide SSH keys are not used
        Level: 1 | Type: Manual | HIGH
        """
        findings = []
        try:
            # This would check project metadata for SSH keys in real implementation
            # For now, return mock findings
            pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.2",
                    title="Unable to Check Project-Wide SSH Keys",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="gcp:vm:ssh-keys",
                    description=f"Could not verify project-wide SSH keys: {str(e)}",
                    recommendation="Verify Compute Engine permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def check_os_login(self) -> List[Dict[str, Any]]:
        """
        4.3: Ensure that OS Login is enabled for a project
        Level: 1 | Type: Manual | MEDIUM
        """
        findings = []
        try:
            # This would check project metadata for OS Login in real implementation
            # For now, return mock findings
            pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.3",
                    title="Unable to Check OS Login Configuration",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="gcp:vm:os-login",
                    description=f"Could not verify OS Login configuration: {str(e)}",
                    recommendation="Verify Compute Engine permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def check_serial_port_access(self) -> List[Dict[str, Any]]:
        """
        4.4: Ensure that the serial port access to VM instances is disabled
        Level: 1 | Type: Manual | MEDIUM
        """
        findings = []
        try:
            # This would check instance metadata for serial port access in real implementation
            # For now, return mock findings
            pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.4",
                    title="Unable to Check Serial Port Access",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="gcp:vm:serial-port",
                    description=f"Could not verify serial port access: {str(e)}",
                    recommendation="Verify Compute Engine permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def check_ip_forwarding(self) -> List[Dict[str, Any]]:
        """
        4.5: Ensure that IP forwarding is not enabled on the instance
        Level: 1 | Type: Manual | MEDIUM
        """
        findings = []
        try:
            # This would check instance configuration for IP forwarding in real implementation
            # For now, return mock findings
            pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="vm_4.5",
                    title="Unable to Check IP Forwarding",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="gcp:vm:ip-forwarding",
                    description=f"Could not verify IP forwarding: {str(e)}",
                    recommendation="Verify Compute Engine permissions",
                    compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for Virtual Machines

        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="vm_4.1",
                title="Ensure that instances are not configured to use the default service account (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="gcp:vm:default-service-account",
                description="Instances are configured to use the default service account.",
                recommendation="Configure instances to use custom service accounts instead of the default service account.",
                compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                command="gcloud compute instances list --format='value(name,serviceAccounts[].email)'",
                evidence={"UsingDefaultServiceAccount": True, "ServiceAccountEmail": "123456789012-compute@developer.gserviceaccount.com"}
            ),
            self.create_finding(
                check_id="vm_4.2",
                title="Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="gcp:vm:default-service-account-full-access",
                description="Instances are configured to use the default service account with full access to all Cloud APIs.",
                recommendation="Remove full access to all Cloud APIs from the default service account.",
                compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                command="gcloud projects get-iam-policy PROJECT_ID --flatten='bindings[].members' --format='table(bindings.role)' --filter='bindings.members:123456789012-compute@developer.gserviceaccount.com'",
                evidence={"HasFullAccess": True, "Roles": ["roles/editor", "roles/owner"], "ServiceAccount": "123456789012-compute@developer.gserviceaccount.com"}
            ),
            self.create_finding(
                check_id="vm_4.3",
                title="Ensure that project-wide SSH keys are not used (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="gcp:vm:project-wide-ssh-keys",
                description="Project-wide SSH keys are being used.",
                recommendation="Remove project-wide SSH keys and use instance-specific SSH keys instead.",
                compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                command="gcloud compute project-info describe --format='value(commonInstanceMetadata.items[?key==`ssh-keys`].value)'",
                evidence={"ProjectWideSSHKeys": True, "SSHKeyCount": 3, "Keys": ["ssh-rsa AAAAB3NzaC1yc2E...", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."]}
            ),
            self.create_finding(
                check_id="vm_4.4",
                title="Ensure that OS Login is enabled for a project (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="gcp:vm:os-login",
                description="OS Login is not enabled for the project.",
                recommendation="Enable OS Login for the project to improve security.",
                compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                command="gcloud compute project-info describe --format='value(commonInstanceMetadata.items[?key==`enable-oslogin`].value)'",
                evidence={"OSLoginEnabled": False, "MetadataValue": "FALSE"}
            ),
            self.create_finding(
                check_id="vm_4.5",
                title="Ensure that the serial port access to VM instances is disabled (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="gcp:vm:serial-port-access",
                description="Serial port access to VM instances is not disabled.",
                recommendation="Disable serial port access to VM instances.",
                compliance_standard="CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                command="gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format='value(metadata.items[?key==`serial-port-enable`].value)'",
                evidence={"SerialPortEnabled": True, "MetadataValue": "TRUE"}
            )
        ]