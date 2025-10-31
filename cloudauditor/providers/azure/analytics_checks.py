from typing import Dict, List, Any, Optional
from cloudauditor.providers.azure.base_checker import BaseAzureChecker

class AnalyticsChecker(BaseAzureChecker):
    """
    Checker for Azure Analytics Services security configurations.
    Implements CIS Microsoft Azure Foundations Benchmark v5.0.0 - Section 1
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all Analytics Services security checks.
        """
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        # Implement real Azure API calls here for Analytics checks
        # Example: Check for Databricks workspace security
        # workspaces = self.databricks_client.workspaces.list_by_subscription()
        # for workspace in workspaces:
        #     if not workspace.parameters.enable_public_ip:
        #         findings.append(self.create_finding(...))
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for Analytics Services
        """
        return [
            self.create_finding(
                check_id="analytics_1.1",
                title="Ensure that Azure Databricks workspace is not publicly accessible (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:databricks:workspace-public-access",
                description="Azure Databricks workspace is publicly accessible.",
                recommendation="Configure Azure Databricks workspace to not be publicly accessible by disabling public IP access.",
                compliance_standard="CIS Microsoft Azure Foundations Benchmark v5.0.0",
                command="az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.enablePublicIp'",
                evidence={"PublicAccessEnabled": True, "EnablePublicIp": True}
            ),
            self.create_finding(
                check_id="analytics_1.2",
                title="Ensure that Azure Databricks workspace has proper network security group rules (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:databricks:workspace-nsg-rules",
                description="Azure Databricks workspace has overly permissive network security group rules.",
                recommendation="Configure restrictive network security group rules for Azure Databricks workspace.",
                compliance_standard="CIS Microsoft Azure Foundations Benchmark v5.0.0",
                command="az network nsg rule list --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --query '[].{Name:name,Access:access,Protocol:protocol,SourcePortRange:sourcePortRange,DestinationPortRange:destinationPortRange,SourceAddressPrefix:sourceAddressPrefix,DestinationAddressPrefix:destinationAddressPrefix}'",
                evidence={"OverlyPermissiveRules": True, "Rules": [{"Name": "AllowAll", "Access": "Allow", "Protocol": "*", "SourcePortRange": "*", "DestinationPortRange": "*", "SourceAddressPrefix": "*", "DestinationAddressPrefix": "*"}]}
            ),
            self.create_finding(
                check_id="analytics_1.3",
                title="Ensure that Azure Databricks workspace has encryption enabled (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:databricks:workspace-encryption",
                description="Azure Databricks workspace does not have encryption enabled.",
                recommendation="Enable encryption for Azure Databricks workspace data at rest.",
                compliance_standard="CIS Microsoft Azure Foundations Benchmark v5.0.0",
                command="az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.encryption'",
                evidence={"EncryptionEnabled": False}
            ),
            self.create_finding(
                check_id="analytics_1.4",
                title="Ensure that Azure Databricks workspace has proper access controls (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:databricks:workspace-access-controls",
                description="Azure Databricks workspace has insufficient access controls.",
                recommendation="Implement proper access controls and role-based access control (RBAC) for Azure Databricks workspace.",
                compliance_standard="CIS Microsoft Azure Foundations Benchmark v5.0.0",
                command="az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.workspaceResourceId'",
                evidence={"AccessControlsConfigured": False, "RBACEnabled": False}
            ),
            self.create_finding(
                check_id="analytics_1.5",
                title="Ensure that Azure Databricks workspace has monitoring enabled (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:databricks:workspace-monitoring",
                description="Azure Databricks workspace does not have comprehensive monitoring enabled.",
                recommendation="Enable comprehensive monitoring and logging for Azure Databricks workspace.",
                compliance_standard="CIS Microsoft Azure Foundations Benchmark v5.0.0",
                command="az monitor diagnostic-settings list --resource WORKSPACE_RESOURCE_ID --query '[].{Name:name,Enabled:enabled,Logs:logs}'",
                evidence={"MonitoringEnabled": False, "DiagnosticSettings": []}
            )
        ]
