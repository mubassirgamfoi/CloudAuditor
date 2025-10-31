from typing import Dict, List, Any, Optional
from cloudauditor.providers.azure.base_checker import BaseAzureChecker

class StorageChecker(BaseAzureChecker):
    """
    Checker for Azure Storage Services security configurations.
    Implements CIS Microsoft Azure Storage Services Benchmark v1.0.0
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all Storage Services security checks.
        """
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        # Implement real Azure API calls here for Storage checks
        # Storage Accounts (networking, encryption, protocol)
        # Blob (data protection)
        # Files (protocol, soft delete)
        # Queue (SAS policy)
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for Storage Services aligned to CIS Microsoft Azure Storage Services Benchmark v1.0.0
        """
        benchmark = "CIS Microsoft Azure Storage Services Benchmark v1.0.0"
        return [
            # Storage Accounts - Networking and Access
            self.create_finding(
                check_id="azstor_17.2.2",
                title="Ensure that 'Public Network Access' is 'Disabled' for storage accounts (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:storage:account-public-network-access",
                description="Storage account allows public network access.",
                recommendation="Disable public network access or restrict to selected networks and IPs.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query publicNetworkAccess",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
            self.create_finding(
                check_id="azstor_17.2.3",
                title="Ensure Default Network Access Rule for Storage Accounts is Set to Deny (Automated)",
                severity="HIGH",
                status="WARNING",
                resource_id="azure:storage:account-default-action",
                description="Default network access rule is not set to Deny.",
                recommendation="Set defaultAction to Deny and allow-list required VNets/IPs only.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query networkRuleSet.defaultAction",
                evidence={"defaultAction": "Allow"}
            ),
            self.create_finding(
                check_id="azstor_17.6",
                title="Ensure 'Allow Azure services on the trusted services list' is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:account-bypass-azureservices",
                description="Trusted Microsoft services bypass is not enabled while firewalls are on.",
                recommendation="Enable bypass for AzureServices when restricting network access.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query networkRuleSet.bypass",
                evidence={"bypass": "None"}
            ),
            # Storage Accounts - Security settings
            self.create_finding(
                check_id="azstor_17.4",
                title="Ensure that 'Secure transfer required' is set to 'Enabled' (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:storage:account-secure-transfer",
                description="Secure transfer is disabled; HTTP requests could be accepted.",
                recommendation="Enable HTTPS-only (secure transfer required) on the storage account.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query enableHttpsTrafficOnly",
                evidence={"enableHttpsTrafficOnly": False}
            ),
            self.create_finding(
                check_id="azstor_17.11",
                title="Ensure the 'Minimum TLS version' is set to 'Version 1.2' (Automated)",
                severity="HIGH",
                status="WARNING",
                resource_id="azure:storage:account-min-tls",
                description="Minimum TLS version is lower than 1.2.",
                recommendation="Set minimum TLS version to TLS 1.2 on the storage account.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query minimumTlsVersion",
                evidence={"minimumTlsVersion": "TLS1_0"}
            ),
            self.create_finding(
                check_id="azstor_17.1.5",
                title="Ensure 'Allow storage account key access' is 'Disabled' (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:account-shared-key-access",
                description="Shared Key authorization is allowed; prefer Entra ID authorization.",
                recommendation="Disable Shared Key access to require Entra ID authorization.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowSharedKeyAccess",
                evidence={"allowSharedKeyAccess": True}
            ),
            self.create_finding(
                check_id="azstor_17.12",
                title="Ensure 'Cross Tenant Replication' is not enabled (Automated)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="azure:storage:account-cross-tenant-repl",
                description="Cross-tenant replication is disabled.",
                recommendation="Keep cross-tenant replication disabled unless explicitly required.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowCrossTenantReplication",
                evidence={"allowCrossTenantReplication": False}
            ),
            self.create_finding(
                check_id="azstor_17.5",
                title="Ensure 'Enable Infrastructure Encryption' is set to 'enabled' (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:account-infra-encryption",
                description="Infrastructure (double) encryption is not enabled.",
                recommendation="Enable infrastructure encryption for higher assurance on sensitive data.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query requireInfrastructureEncryption",
                evidence={"requireInfrastructureEncryption": False}
            ),
            # Blob service
            self.create_finding(
                check_id="azstor_11.3",
                title="Ensure soft delete for blobs is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:blob-soft-delete",
                description="Blob soft delete is not enabled.",
                recommendation="Enable blob soft delete and set appropriate retention days.",
                compliance_standard=benchmark,
                command="az storage blob service-properties delete-policy show --account-name <STORAGE_ACCOUNT>",
                evidence={"deletePolicy": {"enabled": False, "days": None}}
            ),
            self.create_finding(
                check_id="azstor_17.7",
                title="Ensure Soft Delete is Enabled for Containers and Blob Storage (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:container-soft-delete",
                description="Container soft delete is not enabled.",
                recommendation="Enable container soft delete with appropriate retention.",
                compliance_standard=benchmark,
                command="az storage account blob-service-properties show --account-name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP>",
                evidence={"containerDeleteRetentionPolicy": {"enabled": False, "days": None}}
            ),
            self.create_finding(
                check_id="azstor_11.5",
                title="Ensure 'Versioning' is set to 'Enabled' on Blob Storage (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:storage:blob-versioning",
                description="Blob versioning is disabled.",
                recommendation="Enable blob versioning; consider lifecycle to manage costs.",
                compliance_standard=benchmark,
                command="az storage account blob-service-properties show --account-name <STORAGE_ACCOUNT>",
                evidence={"isVersioningEnabled": False}
            ),
            self.create_finding(
                check_id="azstor_11.6",
                title="Ensure locked immutability policies are used for critical containers (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:blob-immutability",
                description="No locked immutability policy on critical containers.",
                recommendation="Create and lock immutability policies for business-critical data.",
                compliance_standard=benchmark,
                command="az storage container immutability-policy show --account-name <STORAGE_ACCOUNT> --container <CONTAINER>",
                evidence={"state": "Unlocked"}
            ),
            self.create_finding(
                check_id="azstor_17.13",
                title="Ensure 'Allow Blob Anonymous Access' is set to 'Disabled' (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:storage:blob-anon-access",
                description="Anonymous blob access is permitted by the account.",
                recommendation="Disable anonymous blob access at the storage account level.",
                compliance_standard=benchmark,
                command="az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowBlobPublicAccess",
                evidence={"allowBlobPublicAccess": True}
            ),
            # Azure Files
            self.create_finding(
                check_id="azstor_8.1",
                title="Ensure soft delete for Azure File Shares is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:files-soft-delete",
                description="File share soft delete is disabled.",
                recommendation="Enable files soft delete and set retention days.",
                compliance_standard=benchmark,
                command="az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT>",
                evidence={"shareDeleteRetentionPolicy": {"enabled": False, "days": None}}
            ),
            self.create_finding(
                check_id="azstor_8.3",
                title="Ensure 'SMB protocol version' is 'SMB 3.1.1' or higher (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:files-smb-version",
                description="SMB protocol allows versions lower than 3.1.1.",
                recommendation="Restrict SMB protocol versions to SMB3.1.1 only.",
                compliance_standard=benchmark,
                command="az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT> --query protocolSettings.smb.versions",
                evidence={"versions": "SMB2.1,SMB3.0,SMB3.1.1"}
            ),
            self.create_finding(
                check_id="azstor_8.4",
                title="Ensure 'SMB channel encryption' is 'AES-256-GCM' or higher (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:storage:files-smb-encryption",
                description="SMB channel encryption includes weaker algorithms.",
                recommendation="Require AES-256-GCM for SMB channel encryption.",
                compliance_standard=benchmark,
                command="az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT> --query protocolSettings.smb.channelEncryption",
                evidence={"channelEncryption": "AES-128-CCM,AES-128-GCM,AES-256-GCM"}
            ),
            # Queue - SAS policy references (manual)
            self.create_finding(
                check_id="azstor_16.1",
                title="Ensure 'Allowed Protocols' for SAS tokens is 'HTTPS Only' (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:storage:queue-sas-https",
                description="SAS issuance process must ensure HTTPS-only.",
                recommendation="When generating SAS, restrict to HTTPS via policy/process.",
                compliance_standard=benchmark,
                command="(Manual) Validate SAS creation templates/enforcement",
                evidence={"policy": "Not enforced"}
            ),
            self.create_finding(
                check_id="azstor_16.2",
                title="Ensure SAS tokens expire within an hour (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:storage:queue-sas-expiry",
                description="SAS token expiry practice exceeds 1 hour.",
                recommendation="Set SAS expiry <= 1 hour; prefer stored access policies.",
                compliance_standard=benchmark,
                command="(Manual) Review SAS issuance configuration",
                evidence={"defaultExpiryHours": 8}
            ),
            self.create_finding(
                check_id="azstor_16.3",
                title="Ensure stored access policies (SAP) are used for SAS (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:storage:queue-sas-sap",
                description="SAS issuance does not use stored access policies.",
                recommendation="Create and use stored access policies for SAS issuance.",
                compliance_standard=benchmark,
                command="(Manual) Review SAS tokens for 'si' parameter",
                evidence={"storedAccessPolicyUsed": False}
            ),
            # Backup vaults (Azure Backup)
            self.create_finding(
                check_id="azstor_5.1.1",
                title="Ensure soft delete on Backup vaults is Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:backup:backup-vault-soft-delete",
                description="Soft delete is not enabled on Backup vault.",
                recommendation="Enable soft delete with appropriate retention (14-180 days).",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"softDeleteSettings": {"state": "Off", "retentionDurationInDays": None}}
            ),
            self.create_finding(
                check_id="azstor_5.1.2",
                title="Ensure immutability for Backup vaults is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:backup-vault-immutability",
                description="Immutability is not enabled on Backup vault.",
                recommendation="Enable and consider locking immutability on Backup vaults.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"immutabilitySettings": {"state": "Disabled"}}
            ),
            self.create_finding(
                check_id="azstor_5.1.3",
                title="Ensure Backup vaults use customer-managed keys (CMK) (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:backup-vault-cmk",
                description="Backup vault uses Microsoft-managed keys.",
                recommendation="Configure CMK and grant vault access to the key in Key Vault.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"securitySettings": {"encryptionSettings": {"keyVaultProperties": None}}}
            ),
            self.create_finding(
                check_id="azstor_5.1.4",
                title="Ensure 'Use infrastructure encryption for this vault' is enabled (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:backup:backup-vault-infra-encryption",
                description="Infrastructure encryption not enabled on Backup vault.",
                recommendation="Enable infrastructure encryption alongside CMK.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"securitySettings": {"encryptionSettings": {"infrastructureEncryption": "Disabled"}}}
            ),
            self.create_finding(
                check_id="azstor_5.1.6",
                title="Ensure 'Cross Subscription Restore' is Disabled on Backup vaults (Automated)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="azure:backup:backup-vault-csr",
                description="Cross subscription restore is disabled.",
                recommendation="Keep CSR disabled unless absolutely necessary.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"featureSettings": {"crossSubscriptionRestoreSettings": {"state": "Disabled"}}}
            ),
            # Recovery Services vaults
            self.create_finding(
                check_id="azstor_5.2.1",
                title="Ensure soft delete on Recovery Services vaults is Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:backup:rsv-soft-delete",
                description="Soft delete is disabled on Recovery Services vault.",
                recommendation="Enable soft delete for cloud and hybrid workloads and set retention.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV>",
                evidence={"softDeleteSettings": {"softDeleteState": "Disabled", "softDeleteRetentionPeriodInDays": None}}
            ),
            self.create_finding(
                check_id="azstor_5.2.2",
                title="Ensure immutability for Recovery Services vaults is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:rsv-immutability",
                description="Immutability is not enabled on Recovery Services vault.",
                recommendation="Enable and consider locking immutability on Recovery Services vaults.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV>",
                evidence={"immutabilitySettings": {"state": "Disabled"}}
            ),
            self.create_finding(
                check_id="azstor_5.2.3",
                title="Ensure Recovery Services vaults use customer-managed keys (CMK) (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:rsv-cmk",
                description="Recovery Services vault uses Microsoft-managed keys.",
                recommendation="Configure CMK for the Recovery Services vault and assign permissions.",
                compliance_standard=benchmark,
                command="az backup vault encryption show --resource-group <RG> --name <RSV>",
                evidence={"properties": {"encryptionAtRestType": "MicrosoftManaged"}}
            ),
            self.create_finding(
                check_id="azstor_5.2.5",
                title="Ensure public network access on Recovery Services vaults is Disabled (Automated)",
                severity="HIGH",
                status="WARNING",
                resource_id="azure:backup:rsv-pna",
                description="Public network access is enabled on Recovery Services vault.",
                recommendation="Disable public network access and use private endpoints.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV> --query properties.publicNetworkAccess",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
            # Elastic SAN
            self.create_finding(
                check_id="azstor_15.1",
                title="Ensure 'Public network access' is 'Disabled' on Azure Elastic SAN (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:elasticsan:public-network-access",
                description="Elastic SAN allows public network access.",
                recommendation="Disable public network access on Elastic SAN.",
                compliance_standard=benchmark,
                command="az elastic-san show --resource-group <RG> --name <ELASTICSAN> --query publicNetworkAccess",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
            self.create_finding(
                check_id="azstor_15.2",
                title="Ensure CMK is used to encrypt data at rest on Elastic SAN volume groups (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:elasticsan:vg-cmk",
                description="Elastic SAN volume group not using customer-managed keys.",
                recommendation="Assign identity and configure CMK for volume groups.",
                compliance_standard=benchmark,
                command="az elastic-san volume-group show --resource-group <RG> --elastic-san <ELASTICSAN> --volume-group <VG>",
                evidence={"encryption": "EncryptionAtRestWithPlatformKey"}
            ),
            # NetApp Files
            self.create_finding(
                check_id="azstor_10.1",
                title="Ensure 'Encryption key source' is 'Customer Managed Key' for Azure NetApp Files (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:anf:cmk",
                description="Azure NetApp Files account is not configured with CMK.",
                recommendation="Configure Customer Managed Key via Key Vault for ANF accounts.",
                compliance_standard=benchmark,
                command="az netappfiles account show --resource-group <RG> --account-name <ANF_ACCOUNT> --query encryption.keySource",
                evidence={"keySource": "Microsoft.NetApp"}
            ),
            # Backup vaults
            self.create_finding(
                check_id="azstor_5.1.1",
                title="Ensure soft delete on Backup vaults is Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:backup:vault-soft-delete",
                description="Backup vault soft delete is disabled or retention not set.",
                recommendation="Enable soft delete and set retention between 14 and 180 days.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"softDeleteSettings": {"state": "Off", "retentionDurationInDays": None}}
            ),
            self.create_finding(
                check_id="azstor_5.1.2",
                title="Ensure immutability for Backup vaults is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:vault-immutability",
                description="Backup vault immutability is not enabled/locked.",
                recommendation="Enable and lock immutability on Backup vaults where appropriate.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"immutabilitySettings": {"state": "Disabled"}}
            ),
            self.create_finding(
                check_id="azstor_5.1.3",
                title="Ensure backup data in Backup vaults uses CMK (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:backup:vault-cmk",
                description="Backup vault not configured with customer-managed keys.",
                recommendation="Configure CMK with proper identity and Key Vault permissions.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.securitySettings.encryptionSettings",
                evidence={"keyVaultProperties": None}
            ),
            self.create_finding(
                check_id="azstor_5.1.4",
                title="Ensure 'Use infrastructure encryption for this vault' is enabled (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:backup:vault-infra-encryption",
                description="Infrastructure encryption not enabled on Backup vault.",
                recommendation="Enable infrastructure encryption in conjunction with CMK.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>",
                evidence={"infrastructureEncryption": "Disabled"}
            ),
            self.create_finding(
                check_id="azstor_5.1.5",
                title="Ensure 'Cross Region Restore' is 'Enabled' on Backup vaults (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:backup:vault-crr",
                description="Cross Region Restore is disabled on Backup vault.",
                recommendation="Enable CRR if aligned with DR strategy and redundancy type.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.featureSettings.crossRegionRestoreSettings.state",
                evidence={"crossRegionRestore": "Disabled"}
            ),
            self.create_finding(
                check_id="azstor_5.1.6",
                title="Ensure 'Cross Subscription Restore' is 'Disabled' or 'Permanently Disabled' (Automated)",
                severity="MEDIUM",
                status="FAILED",
                resource_id="azure:backup:vault-csr",
                description="Cross Subscription Restore is enabled increasing data exposure risk.",
                recommendation="Disable or permanently disable cross subscription restore.",
                compliance_standard=benchmark,
                command="az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.featureSettings.crossSubscriptionRestoreSettings.state",
                evidence={"crossSubscriptionRestore": "Enabled"}
            ),
            # Recovery Services vaults
            self.create_finding(
                check_id="azstor_5.2.1",
                title="Ensure soft delete on Recovery Services vaults is Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:rsv:vault-soft-delete",
                description="Recovery Services vault soft delete and security features not enabled.",
                recommendation="Enable soft delete for cloud and hybrid workloads and set retention 14-180 days.",
                compliance_standard=benchmark,
                command="az backup vault backup-properties show --resource-group <RG> --name <RSV>",
                evidence={"softDeleteFeatureState": "Disable", "softDeleteDuration": None, "hybridBackupSecurityFeatures": "Disable"}
            ),
            self.create_finding(
                check_id="azstor_5.2.2",
                title="Ensure immutability for Recovery Services vaults is Enabled (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:rsv:vault-immutability",
                description="Recovery Services vault immutability is not enabled/locked.",
                recommendation="Enable and lock immutability on Recovery Services vaults as appropriate.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV>",
                evidence={"immutabilitySettings": {"state": "Disabled"}}
            ),
            self.create_finding(
                check_id="azstor_5.2.3",
                title="Ensure backup data in RSV uses CMK (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:rsv:vault-cmk",
                description="Recovery Services vault not configured with customer-managed key.",
                recommendation="Configure CMK with proper identity and Key Vault permissions for RSV.",
                compliance_standard=benchmark,
                command="az backup vault encryption show --resource-group <RG> --name <RSV>",
                evidence={"encryptionAtRestType": "MicrosoftManaged", "keyUri": None}
            ),
            self.create_finding(
                check_id="azstor_5.2.4",
                title="Ensure 'Use infrastructure encryption for this vault' is enabled on RSV (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:rsv:vault-infra-encryption",
                description="Infrastructure encryption not enabled on Recovery Services vault.",
                recommendation="Enable infrastructure encryption with CMK for RSV.",
                compliance_standard=benchmark,
                command="az backup vault encryption show --resource-group <RG> --name <RSV>",
                evidence={"infrastructureEncryptionState": "Disabled"}
            ),
            self.create_finding(
                check_id="azstor_5.2.5",
                title="Ensure public network access on Recovery Services vaults is Disabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:rsv:vault-public-network-access",
                description="Recovery Services vault allows public network access.",
                recommendation="Disable public network access and use private endpoints where supported.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV> --query properties.publicNetworkAccess",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
            self.create_finding(
                check_id="azstor_5.2.6",
                title="Ensure 'Cross Region Restore' is 'Enabled' on RSV (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:rsv:vault-crr",
                description="Cross Region Restore is disabled on Recovery Services vault.",
                recommendation="Enable CRR if aligned with DR strategy and redundancy.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV> --query properties.redundancySettings.crossRegionRestore",
                evidence={"crossRegionRestore": "Disabled"}
            ),
            self.create_finding(
                check_id="azstor_5.2.7",
                title="Ensure 'Cross Subscription Restore' is 'Disabled' or 'Permanently Disabled' on RSV (Automated)",
                severity="MEDIUM",
                status="FAILED",
                resource_id="azure:rsv:vault-csr",
                description="RSV Cross Subscription Restore is enabled increasing data exposure risk.",
                recommendation="Disable or permanently disable cross subscription restore on RSV.",
                compliance_standard=benchmark,
                command="az backup vault show --resource-group <RG> --name <RSV> --query properties.restoreSettings.crossSubscriptionRestoreSettings.crossSubscriptionRestoreState",
                evidence={"crossSubscriptionRestoreState": "Enabled"}
            ),
            # Elastic SAN
            self.create_finding(
                check_id="azstor_15.1",
                title="Ensure 'Public network access' is set to 'Disabled' on Azure Elastic SAN (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:elasticsan:public-network-access",
                description="Elastic SAN public network access is enabled.",
                recommendation="Disable public network access at the SAN level.",
                compliance_standard=benchmark,
                command="az elastic-san show --resource-group <RG> --name <ELASTIC_SAN> --query publicNetworkAccess",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
            self.create_finding(
                check_id="azstor_15.2",
                title="Ensure CMK is used to encrypt data at rest on Elastic SAN volume groups (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:elasticsan:vg-cmk",
                description="Elastic SAN volume group not configured for CMK encryption.",
                recommendation="Configure EncryptionAtRestWithCustomerManagedKey with proper Key Vault settings.",
                compliance_standard=benchmark,
                command="az elastic-san volume-group show --resource-group <RG> --elastic-san <ELASTIC_SAN> --name <VG> --query encryption",
                evidence={"encryption": "EncryptionAtRestWithPlatformKey"}
            ),
            # NetApp Files
            self.create_finding(
                check_id="azstor_10.1",
                title="Ensure 'Encryption key source' is 'Customer Managed Key' for Azure NetApp Files accounts (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:anf:account-cmk",
                description="NetApp Files account uses platform-managed encryption keys.",
                recommendation="Switch Encryption key source to Customer Managed Key and select CMK in Key Vault.",
                compliance_standard=benchmark,
                command="az netappfiles account show --resource-group <RG> --account-name <ANF> --query encryption.keySource",
                evidence={"keySource": "Microsoft.NetApp"}
            ),
        ]
