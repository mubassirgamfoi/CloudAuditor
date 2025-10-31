from typing import Dict, List, Any, Optional
from cloudauditor.providers.azure.base_checker import BaseAzureChecker

class ComputeChecker(BaseAzureChecker):
    """
    Checker for Azure Compute Services security configurations.
    Implements CIS Microsoft Azure Compute Services Benchmark v2.0.0
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all Azure Compute Services security checks.
        """
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        # TODO: Implement real Azure API calls per service (AKS, App Service, Functions, VMs/VMSS, ACI, etc.)
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for Azure Compute Services (representative subset)
        """
        cs = "CIS Microsoft Azure Compute Services Benchmark v2.0.0"
        return [
            self.create_finding(
                check_id="azure_compute_1.1",
                title="Ensure App Service apps enforce HTTPS only",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:appservice:webapp-https-only",
                description="App Service app allows HTTP connections.",
                recommendation="Enable HTTPS-only setting for all App Service apps.",
                compliance_standard=cs,
                command="az webapp show --name APP_NAME --resource-group RG --query httpsOnly",
                evidence={"httpsOnly": False}
            ),
            self.create_finding(
                check_id="azure_compute_1.2",
                title="Ensure App Service FTPS is enforced and FTP is disabled",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:appservice:webapp-ftp-disabled",
                description="App Service app allows FTP.",
                recommendation="Set FTPS state to 'FtpsOnly' and disable FTP.",
                compliance_standard=cs,
                command="az webapp config show --name APP_NAME --resource-group RG --query ftpsState",
                evidence={"ftpsState": "AllAllowed"}
            ),
            self.create_finding(
                check_id="azure_compute_2.1",
                title="Ensure AKS local accounts are disabled",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:aks:local-accounts",
                description="AKS cluster allows local accounts.",
                recommendation="Disable local accounts on AKS clusters.",
                compliance_standard=cs,
                command="az aks show --name CLUSTER --resource-group RG --query apiServerAccessProfile.disableLocalAccounts",
                evidence={"disableLocalAccounts": False}
            ),
            self.create_finding(
                check_id="azure_compute_2.2",
                title="Ensure AKS RBAC is enabled",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:aks:rbac",
                description="AKS cluster has RBAC disabled.",
                recommendation="Create AKS clusters with --enable-rbac or ensure RBAC is enabled.",
                compliance_standard=cs,
                command="az aks show --name CLUSTER --resource-group RG --query enableRBAC",
                evidence={"enableRBAC": False}
            ),
            self.create_finding(
                check_id="azure_compute_3.1",
                title="Ensure Function Apps require HTTPS",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:functionapp:https-only",
                description="Function App allows HTTP traffic.",
                recommendation="Enable HTTPS-only on all Function Apps.",
                compliance_standard=cs,
                command="az functionapp show --name FUNC_NAME --resource-group RG --query httpsOnly",
                evidence={"httpsOnly": False}
            ),
            self.create_finding(
                check_id="azure_compute_3.2",
                title="Ensure Function Apps use a system-assigned managed identity",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:functionapp:identity",
                description="Function App does not have a managed identity.",
                recommendation="Enable system-assigned managed identity on Function Apps.",
                compliance_standard=cs,
                command="az functionapp identity show --name FUNC_NAME --resource-group RG --query '{type:type,principalId:principalId}'",
                evidence={"type": "None", "principalId": None}
            ),
            self.create_finding(
                check_id="azure_compute_4.1",
                title="Ensure App Service minimum TLS version is 1.2 or higher",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:appservice:min-tls",
                description="App Service app allows TLS versions below 1.2.",
                recommendation="Set minimum TLS version to 1.2 or higher.",
                compliance_standard=cs,
                command="az webapp config show --name APP_NAME --resource-group RG --query minTlsVersion",
                evidence={"minTlsVersion": "1.0"}
            ),
            self.create_finding(
                check_id="azure_compute_5.1",
                title="Ensure VM disks are encrypted with customer-managed keys (CMK)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:compute:vm-cmk",
                description="VM disks are not encrypted with CMK.",
                recommendation="Configure Disk Encryption Set with CMK and attach to VM disks.",
                compliance_standard=cs,
                command="az vm show --name VM_NAME --resource-group RG --query storageProfile.osDisk.managedDisk.diskEncryptionSet.id",
                evidence={"diskEncryptionSetId": None}
            ),
            self.create_finding(
                check_id="azure_compute_5.2",
                title="Ensure VM Scale Sets have encryption at host enabled",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:compute:vmss-encryption-at-host",
                description="VMSS does not have encryptionAtHost enabled.",
                recommendation="Enable encryptionAtHost on VM Scale Sets.",
                compliance_standard=cs,
                command="az vmss show --name VMSS_NAME --resource-group RG --query virtualMachineProfile.securityProfile.encryptionAtHost",
                evidence={"encryptionAtHost": False}
            ),
            self.create_finding(
                check_id="azure_compute_6.1",
                title="Ensure Azure Container Instances are not exposed publicly",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:aci:public-ip",
                description="ACI container group has a public IP address.",
                recommendation="Deploy ACI in a VNET without public IP and use private endpoints.",
                compliance_standard=cs,
                command="az container show --name ACI_NAME --resource-group RG --query ipAddress.type",
                evidence={"ipAddress": {"type": "Public"}}
            ),
            self.create_finding(
                check_id="azure_compute_7.1",
                title="Ensure Azure Virtual Desktop requires MFA for client access",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:avd:mfa",
                description="AVD client access does not require MFA.",
                recommendation="Enforce MFA via Conditional Access for Azure Virtual Desktop.",
                compliance_standard=cs,
                command="(Policy) az rest --method get --url 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'",
                evidence={"conditionalAccess": "No policy targeting AVD requiring MFA"}
            ),
            self.create_finding(
                check_id="azure_compute_8.1",
                title="Ensure Azure Kubernetes Service enables Azure Policy add-on",
                severity="LOW",
                status="WARNING",
                resource_id="azure:aks:azure-policy",
                description="AKS cluster does not have the Azure Policy add-on enabled.",
                recommendation="Enable --enable-addons azure-policy on AKS clusters.",
                compliance_standard=cs,
                command="az aks show --name CLUSTER --resource-group RG --query addonProfiles.azurepolicy.enabled",
                evidence={"addonProfiles": {"azurepolicy": {"enabled": False}}}
            ),
        ]
