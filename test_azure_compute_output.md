# CloudAuditor Compliance Report

**Generated:** 2025-10-30T02:20:40.665361
**Provider:** AZURE
**Command:** `cloudauditor scan azure --profile test-subscription --output markdown --output-file test_azure_compute_output.md`

## Benchmarks Executed
- CIS Microsoft Azure Foundations Benchmark v5.0.0
- CIS Microsoft Azure Compute Services Benchmark v2.0.0
- CIS Microsoft Azure Storage Services Benchmark v1.0.0
- CIS Microsoft Azure Database Services Benchmark v1.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 2
- **Failed:** 27
- **Warnings:** 74

## Findings

### 1. Ensure that Azure Databricks workspace is not publicly accessible (Manual)
- **Check ID:** `analytics_1.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:databricks:workspace-public-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Databricks workspace is publicly accessible.

**Recommendation (CIS):** Configure Azure Databricks workspace to not be publicly accessible by disabling public IP access.

**Command Executed:**

```
az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.enablePublicIp'
```

**Evidence/Output:**

```
{'PublicAccessEnabled': True, 'EnablePublicIp': True}
```

---

### 2. Ensure that Azure Databricks workspace has proper network security group rules (Manual)
- **Check ID:** `analytics_1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:databricks:workspace-nsg-rules`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Databricks workspace has overly permissive network security group rules.

**Recommendation (CIS):** Configure restrictive network security group rules for Azure Databricks workspace.

**Command Executed:**

```
az network nsg rule list --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --query '[].{Name:name,Access:access,Protocol:protocol,SourcePortRange:sourcePortRange,DestinationPortRange:destinationPortRange,SourceAddressPrefix:sourceAddressPrefix,DestinationAddressPrefix:destinationAddressPrefix}'
```

**Evidence/Output:**

```
{'OverlyPermissiveRules': True, 'Rules': [{'Name': 'AllowAll', 'Access': 'Allow', 'Protocol': '*', 'SourcePortRange': '*', 'DestinationPortRange': '*', 'SourceAddressPrefix': '*', 'DestinationAddressPrefix': '*'}]}
```

---

### 3. Ensure that Azure Databricks workspace has encryption enabled (Manual)
- **Check ID:** `analytics_1.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:databricks:workspace-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Databricks workspace does not have encryption enabled.

**Recommendation (CIS):** Enable encryption for Azure Databricks workspace data at rest.

**Command Executed:**

```
az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.encryption'
```

**Evidence/Output:**

```
{'EncryptionEnabled': False}
```

---

### 4. Ensure that Azure Databricks workspace has proper access controls (Manual)
- **Check ID:** `analytics_1.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:databricks:workspace-access-controls`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Databricks workspace has insufficient access controls.

**Recommendation (CIS):** Implement proper access controls and role-based access control (RBAC) for Azure Databricks workspace.

**Command Executed:**

```
az databricks workspace show --name WORKSPACE_NAME --resource-group RESOURCE_GROUP --query 'parameters.workspaceResourceId'
```

**Evidence/Output:**

```
{'AccessControlsConfigured': False, 'RBACEnabled': False}
```

---

### 5. Ensure that Azure Databricks workspace has monitoring enabled (Manual)
- **Check ID:** `analytics_1.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:databricks:workspace-monitoring`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Databricks workspace does not have comprehensive monitoring enabled.

**Recommendation (CIS):** Enable comprehensive monitoring and logging for Azure Databricks workspace.

**Command Executed:**

```
az monitor diagnostic-settings list --resource WORKSPACE_RESOURCE_ID --query '[].{Name:name,Enabled:enabled,Logs:logs}'
```

**Evidence/Output:**

```
{'MonitoringEnabled': False, 'DiagnosticSettings': []}
```

---

### 6. Ensure App Service apps enforce HTTPS only
- **Check ID:** `azure_compute_1.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:appservice:webapp-https-only`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** App Service app allows HTTP connections.

**Recommendation (CIS):** Enable HTTPS-only setting for all App Service apps.

**Command Executed:**

```
az webapp show --name APP_NAME --resource-group RG --query httpsOnly
```

**Evidence/Output:**

```
{'httpsOnly': False}
```

---

### 7. Ensure App Service FTPS is enforced and FTP is disabled
- **Check ID:** `azure_compute_1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:appservice:webapp-ftp-disabled`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** App Service app allows FTP.

**Recommendation (CIS):** Set FTPS state to 'FtpsOnly' and disable FTP.

**Command Executed:**

```
az webapp config show --name APP_NAME --resource-group RG --query ftpsState
```

**Evidence/Output:**

```
{'ftpsState': 'AllAllowed'}
```

---

### 8. Ensure AKS local accounts are disabled
- **Check ID:** `azure_compute_2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:aks:local-accounts`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** AKS cluster allows local accounts.

**Recommendation (CIS):** Disable local accounts on AKS clusters.

**Command Executed:**

```
az aks show --name CLUSTER --resource-group RG --query apiServerAccessProfile.disableLocalAccounts
```

**Evidence/Output:**

```
{'disableLocalAccounts': False}
```

---

### 9. Ensure AKS RBAC is enabled
- **Check ID:** `azure_compute_2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:aks:rbac`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** AKS cluster has RBAC disabled.

**Recommendation (CIS):** Create AKS clusters with --enable-rbac or ensure RBAC is enabled.

**Command Executed:**

```
az aks show --name CLUSTER --resource-group RG --query enableRBAC
```

**Evidence/Output:**

```
{'enableRBAC': False}
```

---

### 10. Ensure Function Apps require HTTPS
- **Check ID:** `azure_compute_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:functionapp:https-only`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** Function App allows HTTP traffic.

**Recommendation (CIS):** Enable HTTPS-only on all Function Apps.

**Command Executed:**

```
az functionapp show --name FUNC_NAME --resource-group RG --query httpsOnly
```

**Evidence/Output:**

```
{'httpsOnly': False}
```

---

### 11. Ensure Function Apps use a system-assigned managed identity
- **Check ID:** `azure_compute_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:functionapp:identity`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** Function App does not have a managed identity.

**Recommendation (CIS):** Enable system-assigned managed identity on Function Apps.

**Command Executed:**

```
az functionapp identity show --name FUNC_NAME --resource-group RG --query '{type:type,principalId:principalId}'
```

**Evidence/Output:**

```
{'type': 'None', 'principalId': None}
```

---

### 12. Ensure App Service minimum TLS version is 1.2 or higher
- **Check ID:** `azure_compute_4.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:appservice:min-tls`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** App Service app allows TLS versions below 1.2.

**Recommendation (CIS):** Set minimum TLS version to 1.2 or higher.

**Command Executed:**

```
az webapp config show --name APP_NAME --resource-group RG --query minTlsVersion
```

**Evidence/Output:**

```
{'minTlsVersion': '1.0'}
```

---

### 13. Ensure VM disks are encrypted with customer-managed keys (CMK)
- **Check ID:** `azure_compute_5.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:compute:vm-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** VM disks are not encrypted with CMK.

**Recommendation (CIS):** Configure Disk Encryption Set with CMK and attach to VM disks.

**Command Executed:**

```
az vm show --name VM_NAME --resource-group RG --query storageProfile.osDisk.managedDisk.diskEncryptionSet.id
```

**Evidence/Output:**

```
{'diskEncryptionSetId': None}
```

---

### 14. Ensure VM Scale Sets have encryption at host enabled
- **Check ID:** `azure_compute_5.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:compute:vmss-encryption-at-host`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** VMSS does not have encryptionAtHost enabled.

**Recommendation (CIS):** Enable encryptionAtHost on VM Scale Sets.

**Command Executed:**

```
az vmss show --name VMSS_NAME --resource-group RG --query virtualMachineProfile.securityProfile.encryptionAtHost
```

**Evidence/Output:**

```
{'encryptionAtHost': False}
```

---

### 15. Ensure Azure Container Instances are not exposed publicly
- **Check ID:** `azure_compute_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:aci:public-ip`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** ACI container group has a public IP address.

**Recommendation (CIS):** Deploy ACI in a VNET without public IP and use private endpoints.

**Command Executed:**

```
az container show --name ACI_NAME --resource-group RG --query ipAddress.type
```

**Evidence/Output:**

```
{'ipAddress': {'type': 'Public'}}
```

---

### 16. Ensure Azure Virtual Desktop requires MFA for client access
- **Check ID:** `azure_compute_7.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:avd:mfa`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** AVD client access does not require MFA.

**Recommendation (CIS):** Enforce MFA via Conditional Access for Azure Virtual Desktop.

**Command Executed:**

```
(Policy) az rest --method get --url 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
```

**Evidence/Output:**

```
{'conditionalAccess': 'No policy targeting AVD requiring MFA'}
```

---

### 17. Ensure Azure Kubernetes Service enables Azure Policy add-on
- **Check ID:** `azure_compute_8.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:aks:azure-policy`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Compute Services Benchmark v2.0.0

**Description:** AKS cluster does not have the Azure Policy add-on enabled.

**Recommendation (CIS):** Enable --enable-addons azure-policy on AKS clusters.

**Command Executed:**

```
az aks show --name CLUSTER --resource-group RG --query addonProfiles.azurepolicy.enabled
```

**Evidence/Output:**

```
{'addonProfiles': {'azurepolicy': {'enabled': False}}}
```

---

### 18. Ensure that security defaults are enabled (Manual)
- **Check ID:** `identity_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:identity:security-defaults`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Security defaults are not enabled.

**Recommendation (CIS):** Enable security defaults to enforce basic security policies.

**Command Executed:**

```
az ad security-defaults show --query 'isEnabled'
```

**Evidence/Output:**

```
{'SecurityDefaultsEnabled': False, 'IsEnabled': False}
```

---

### 19. Ensure that per-user MFA is enabled (Manual)
- **Check ID:** `identity_3.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:identity:per-user-mfa`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Per-user MFA is not enabled for all users.

**Recommendation (CIS):** Enable per-user MFA for all users.

**Command Executed:**

```
az ad user list --query '[].{DisplayName:displayName,UserPrincipalName:userPrincipalName,StrongAuthenticationDetail:strongAuthenticationDetail}'
```

**Evidence/Output:**

```
{'PerUserMFAEnabled': False, 'UsersWithoutMFA': 15}
```

---

### 20. Ensure that conditional access policies are configured (Manual)
- **Check ID:** `identity_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:identity:conditional-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Conditional access policies are not properly configured.

**Recommendation (CIS):** Configure conditional access policies to enforce additional security controls.

**Command Executed:**

```
az ad conditional-access policy list --query '[].{DisplayName:displayName,State:state,Conditions:conditions}'
```

**Evidence/Output:**

```
{'ConditionalAccessConfigured': False, 'Policies': []}
```

---

### 21. Ensure that periodic identity reviews are configured (Manual)
- **Check ID:** `identity_3.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:identity:periodic-reviews`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Periodic identity reviews are not configured.

**Recommendation (CIS):** Configure periodic identity reviews to ensure proper access management.

**Command Executed:**

```
az ad access-review list --query '[].{DisplayName:displayName,Status:status,Reviewers:reviewers}'
```

**Evidence/Output:**

```
{'PeriodicReviewsConfigured': False, 'AccessReviews': []}
```

---

### 22. Ensure that privileged access is properly managed (Manual)
- **Check ID:** `identity_3.5`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:identity:privileged-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Privileged access is not properly managed.

**Recommendation (CIS):** Implement proper privileged access management (PAM) controls.

**Command Executed:**

```
az ad user list --filter "assignedRoles/any(r:r/roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10')" --query '[].{DisplayName:displayName,UserPrincipalName:userPrincipalName}'
```

**Evidence/Output:**

```
{'PrivilegedAccessManaged': False, 'GlobalAdmins': 3}
```

---

### 23. Ensure that diagnostic settings are configured for all resources (Manual)
- **Check ID:** `logging_4.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:logging:diagnostic-settings`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Diagnostic settings are not configured for all resources.

**Recommendation (CIS):** Configure diagnostic settings for all resources to enable logging and monitoring.

**Command Executed:**

```
az monitor diagnostic-settings list --resource RESOURCE_ID --query '[].{Name:name,Enabled:enabled,Logs:logs}'
```

**Evidence/Output:**

```
{'DiagnosticSettingsConfigured': False, 'ResourcesWithoutLogging': 25}
```

---

### 24. Ensure that activity log alerts are configured (Manual)
- **Check ID:** `logging_4.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:logging:activity-log-alerts`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Activity log alerts are not properly configured.

**Recommendation (CIS):** Configure activity log alerts for critical security events.

**Command Executed:**

```
az monitor activity-log alert list --query '[].{Name:name,Enabled:enabled,Conditions:conditions}'
```

**Evidence/Output:**

```
{'ActivityLogAlertsConfigured': False, 'Alerts': []}
```

---

### 25. Ensure that Application Insights is enabled (Manual)
- **Check ID:** `logging_4.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:logging:application-insights`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Application Insights is not enabled for applications.

**Recommendation (CIS):** Enable Application Insights for comprehensive application monitoring.

**Command Executed:**

```
az monitor app-insights component list --query '[].{Name:name,Enabled:enabled,InstrumentationKey:instrumentationKey}'
```

**Evidence/Output:**

```
{'ApplicationInsightsEnabled': False, 'Components': []}
```

---

### 26. Ensure that Azure Monitor resource logging is enabled (Manual)
- **Check ID:** `logging_4.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:logging:azure-monitor-logging`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Monitor resource logging is not enabled.

**Recommendation (CIS):** Enable Azure Monitor resource logging for comprehensive monitoring.

**Command Executed:**

```
az monitor log-profiles list --query '[].{Name:name,Enabled:enabled,Logs:logs}'
```

**Evidence/Output:**

```
{'AzureMonitorLoggingEnabled': False, 'LogProfiles': []}
```

---

### 27. Ensure that log retention is properly configured (Manual)
- **Check ID:** `logging_4.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:logging:log-retention`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Log retention is not properly configured.

**Recommendation (CIS):** Configure appropriate log retention periods for compliance and security requirements.

**Command Executed:**

```
az monitor log-profiles list --query '[].{Name:name,RetentionDays:retentionPolicy.days}'
```

**Evidence/Output:**

```
{'LogRetentionConfigured': False, 'RetentionDays': 30}
```

---

### 28. Ensure that RDP access is restricted (Manual)
- **Check ID:** `networking_5.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:networking:rdp-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** RDP access is not properly restricted.

**Recommendation (CIS):** Restrict RDP access to specific IP ranges and use strong authentication.

**Command Executed:**

```
az network nsg rule list --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --query '[?protocol==`Tcp` && destinationPortRange==`3389`].{Name:name,Access:access,SourceAddressPrefix:sourceAddressPrefix}'
```

**Evidence/Output:**

```
{'RDPAccessRestricted': False, 'Rules': [{'Name': 'AllowRDP', 'Access': 'Allow', 'SourceAddressPrefix': '*'}]}
```

---

### 29. Ensure that SSH access is restricted (Manual)
- **Check ID:** `networking_5.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:networking:ssh-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** SSH access is not properly restricted.

**Recommendation (CIS):** Restrict SSH access to specific IP ranges and use key-based authentication.

**Command Executed:**

```
az network nsg rule list --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --query '[?protocol==`Tcp` && destinationPortRange==`22`].{Name:name,Access:access,SourceAddressPrefix:sourceAddressPrefix}'
```

**Evidence/Output:**

```
{'SSHAccessRestricted': False, 'Rules': [{'Name': 'AllowSSH', 'Access': 'Allow', 'SourceAddressPrefix': '*'}]}
```

---

### 30. Ensure that NSG flow logs are enabled (Manual)
- **Check ID:** `networking_5.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:networking:nsg-flow-logs`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** NSG flow logs are not enabled.

**Recommendation (CIS):** Enable NSG flow logs for network traffic monitoring and analysis.

**Command Executed:**

```
az network watcher flow-log list --resource-group RESOURCE_GROUP --query '[].{Name:name,Enabled:enabled,TargetResourceId:targetResourceId}'
```

**Evidence/Output:**

```
{'NSGFlowLogsEnabled': False, 'FlowLogs': []}
```

---

### 31. Ensure that Network Watcher is enabled (Manual)
- **Check ID:** `networking_5.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:networking:network-watcher`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Network Watcher is not enabled.

**Recommendation (CIS):** Enable Network Watcher for network monitoring and diagnostics.

**Command Executed:**

```
az network watcher list --query '[].{Name:name,Location:location,ProvisioningState:provisioningState}'
```

**Evidence/Output:**

```
{'NetworkWatcherEnabled': False, 'Watchers': []}
```

---

### 32. Ensure that public IPs are not used unnecessarily (Manual)
- **Check ID:** `networking_5.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:networking:public-ips`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Public IPs are being used unnecessarily.

**Recommendation (CIS):** Use private IPs and load balancers instead of public IPs where possible.

**Command Executed:**

```
az network public-ip list --query '[].{Name:name,ResourceGroup:resourceGroup,PublicIPAllocationMethod:publicIPAllocationMethod}'
```

**Evidence/Output:**

```
{'UnnecessaryPublicIPs': True, 'PublicIPs': [{'Name': 'vm-public-ip', 'ResourceGroup': 'rg-vms', 'PublicIPAllocationMethod': 'Static'}]}
```

---

### 33. Ensure that Microsoft Defender for Cloud is enabled (Manual)
- **Check ID:** `security_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:security:defender-for-cloud`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Microsoft Defender for Cloud is not enabled.

**Recommendation (CIS):** Enable Microsoft Defender for Cloud for comprehensive security monitoring and threat protection.

**Command Executed:**

```
az security pricing list --query '[].{Name:name,Enabled:enabled}'
```

**Evidence/Output:**

```
{'DefenderForCloudEnabled': False, 'PricingTiers': []}
```

---

### 34. Ensure that Key Vault has proper access controls (Manual)
- **Check ID:** `security_6.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:security:key-vault-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Key Vault does not have proper access controls configured.

**Recommendation (CIS):** Configure proper access controls and network restrictions for Key Vault.

**Command Executed:**

```
az keyvault show --name VAULT_NAME --resource-group RESOURCE_GROUP --query '{AccessPolicies:accessPolicies,NetworkAcls:networkAcls}'
```

**Evidence/Output:**

```
{'AccessControlsConfigured': False, 'PublicNetworkAccess': 'Enabled', 'AccessPolicies': []}
```

---

### 35. Ensure that Key Vault has purge protection enabled (Manual)
- **Check ID:** `security_6.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:security:key-vault-purge-protection`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Key Vault does not have purge protection enabled.

**Recommendation (CIS):** Enable purge protection for Key Vault to prevent accidental deletion.

**Command Executed:**

```
az keyvault show --name VAULT_NAME --resource-group RESOURCE_GROUP --query 'properties.enablePurgeProtection'
```

**Evidence/Output:**

```
{'PurgeProtectionEnabled': False, 'EnablePurgeProtection': False}
```

---

### 36. Ensure that Azure Bastion is configured (Manual)
- **Check ID:** `security_6.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:security:azure-bastion`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Bastion is not configured for secure remote access.

**Recommendation (CIS):** Configure Azure Bastion for secure remote access to virtual machines.

**Command Executed:**

```
az network bastion list --query '[].{Name:name,ResourceGroup:resourceGroup,ProvisioningState:provisioningState}'
```

**Evidence/Output:**

```
{'AzureBastionConfigured': False, 'Bastions': []}
```

---

### 37. Ensure that DDoS Network Protection is enabled (Manual)
- **Check ID:** `security_6.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:security:ddos-protection`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** DDoS Network Protection is not enabled.

**Recommendation (CIS):** Enable DDoS Network Protection for network security.

**Command Executed:**

```
az network ddos-protection list --query '[].{Name:name,ResourceGroup:resourceGroup,ProvisioningState:provisioningState}'
```

**Evidence/Output:**

```
{'DDoSProtectionEnabled': False, 'DDoSProtections': []}
```

---

### 38. Ensure that 'Public Network Access' is 'Disabled' for storage accounts (Automated)
- **Check ID:** `azstor_17.2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:storage:account-public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Storage account allows public network access.

**Recommendation (CIS):** Disable public network access or restrict to selected networks and IPs.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query publicNetworkAccess
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---

### 39. Ensure Default Network Access Rule for Storage Accounts is Set to Deny (Automated)
- **Check ID:** `azstor_17.2.3`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:storage:account-default-action`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Default network access rule is not set to Deny.

**Recommendation (CIS):** Set defaultAction to Deny and allow-list required VNets/IPs only.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query networkRuleSet.defaultAction
```

**Evidence/Output:**

```
{'defaultAction': 'Allow'}
```

---

### 40. Ensure 'Allow Azure services on the trusted services list' is Enabled (Automated)
- **Check ID:** `azstor_17.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:account-bypass-azureservices`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Trusted Microsoft services bypass is not enabled while firewalls are on.

**Recommendation (CIS):** Enable bypass for AzureServices when restricting network access.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query networkRuleSet.bypass
```

**Evidence/Output:**

```
{'bypass': 'None'}
```

---

### 41. Ensure that 'Secure transfer required' is set to 'Enabled' (Automated)
- **Check ID:** `azstor_17.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:storage:account-secure-transfer`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Secure transfer is disabled; HTTP requests could be accepted.

**Recommendation (CIS):** Enable HTTPS-only (secure transfer required) on the storage account.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query enableHttpsTrafficOnly
```

**Evidence/Output:**

```
{'enableHttpsTrafficOnly': False}
```

---

### 42. Ensure the 'Minimum TLS version' is set to 'Version 1.2' (Automated)
- **Check ID:** `azstor_17.11`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:storage:account-min-tls`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Minimum TLS version is lower than 1.2.

**Recommendation (CIS):** Set minimum TLS version to TLS 1.2 on the storage account.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query minimumTlsVersion
```

**Evidence/Output:**

```
{'minimumTlsVersion': 'TLS1_0'}
```

---

### 43. Ensure 'Allow storage account key access' is 'Disabled' (Automated)
- **Check ID:** `azstor_17.1.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:account-shared-key-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Shared Key authorization is allowed; prefer Entra ID authorization.

**Recommendation (CIS):** Disable Shared Key access to require Entra ID authorization.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowSharedKeyAccess
```

**Evidence/Output:**

```
{'allowSharedKeyAccess': True}
```

---

### 44. Ensure 'Cross Tenant Replication' is not enabled (Automated)
- **Check ID:** `azstor_17.12`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `azure:storage:account-cross-tenant-repl`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Cross-tenant replication is disabled.

**Recommendation (CIS):** Keep cross-tenant replication disabled unless explicitly required.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowCrossTenantReplication
```

**Evidence/Output:**

```
{'allowCrossTenantReplication': False}
```

---

### 45. Ensure 'Enable Infrastructure Encryption' is set to 'enabled' (Automated)
- **Check ID:** `azstor_17.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:account-infra-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Infrastructure (double) encryption is not enabled.

**Recommendation (CIS):** Enable infrastructure encryption for higher assurance on sensitive data.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query requireInfrastructureEncryption
```

**Evidence/Output:**

```
{'requireInfrastructureEncryption': False}
```

---

### 46. Ensure soft delete for blobs is Enabled (Automated)
- **Check ID:** `azstor_11.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:blob-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Blob soft delete is not enabled.

**Recommendation (CIS):** Enable blob soft delete and set appropriate retention days.

**Command Executed:**

```
az storage blob service-properties delete-policy show --account-name <STORAGE_ACCOUNT>
```

**Evidence/Output:**

```
{'deletePolicy': {'enabled': False, 'days': None}}
```

---

### 47. Ensure Soft Delete is Enabled for Containers and Blob Storage (Automated)
- **Check ID:** `azstor_17.7`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:container-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Container soft delete is not enabled.

**Recommendation (CIS):** Enable container soft delete with appropriate retention.

**Command Executed:**

```
az storage account blob-service-properties show --account-name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP>
```

**Evidence/Output:**

```
{'containerDeleteRetentionPolicy': {'enabled': False, 'days': None}}
```

---

### 48. Ensure 'Versioning' is set to 'Enabled' on Blob Storage (Automated)
- **Check ID:** `azstor_11.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:storage:blob-versioning`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Blob versioning is disabled.

**Recommendation (CIS):** Enable blob versioning; consider lifecycle to manage costs.

**Command Executed:**

```
az storage account blob-service-properties show --account-name <STORAGE_ACCOUNT>
```

**Evidence/Output:**

```
{'isVersioningEnabled': False}
```

---

### 49. Ensure locked immutability policies are used for critical containers (Automated)
- **Check ID:** `azstor_11.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:blob-immutability`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** No locked immutability policy on critical containers.

**Recommendation (CIS):** Create and lock immutability policies for business-critical data.

**Command Executed:**

```
az storage container immutability-policy show --account-name <STORAGE_ACCOUNT> --container <CONTAINER>
```

**Evidence/Output:**

```
{'state': 'Unlocked'}
```

---

### 50. Ensure 'Allow Blob Anonymous Access' is set to 'Disabled' (Automated)
- **Check ID:** `azstor_17.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:storage:blob-anon-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Anonymous blob access is permitted by the account.

**Recommendation (CIS):** Disable anonymous blob access at the storage account level.

**Command Executed:**

```
az storage account show --name <STORAGE_ACCOUNT> --resource-group <RESOURCE_GROUP> --query allowBlobPublicAccess
```

**Evidence/Output:**

```
{'allowBlobPublicAccess': True}
```

---

### 51. Ensure soft delete for Azure File Shares is Enabled (Automated)
- **Check ID:** `azstor_8.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:files-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** File share soft delete is disabled.

**Recommendation (CIS):** Enable files soft delete and set retention days.

**Command Executed:**

```
az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT>
```

**Evidence/Output:**

```
{'shareDeleteRetentionPolicy': {'enabled': False, 'days': None}}
```

---

### 52. Ensure 'SMB protocol version' is 'SMB 3.1.1' or higher (Automated)
- **Check ID:** `azstor_8.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:files-smb-version`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** SMB protocol allows versions lower than 3.1.1.

**Recommendation (CIS):** Restrict SMB protocol versions to SMB3.1.1 only.

**Command Executed:**

```
az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT> --query protocolSettings.smb.versions
```

**Evidence/Output:**

```
{'versions': 'SMB2.1,SMB3.0,SMB3.1.1'}
```

---

### 53. Ensure 'SMB channel encryption' is 'AES-256-GCM' or higher (Automated)
- **Check ID:** `azstor_8.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:files-smb-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** SMB channel encryption includes weaker algorithms.

**Recommendation (CIS):** Require AES-256-GCM for SMB channel encryption.

**Command Executed:**

```
az storage account file-service-properties show --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT> --query protocolSettings.smb.channelEncryption
```

**Evidence/Output:**

```
{'channelEncryption': 'AES-128-CCM,AES-128-GCM,AES-256-GCM'}
```

---

### 54. Ensure 'Allowed Protocols' for SAS tokens is 'HTTPS Only' (Manual)
- **Check ID:** `azstor_16.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:storage:queue-sas-https`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** SAS issuance process must ensure HTTPS-only.

**Recommendation (CIS):** When generating SAS, restrict to HTTPS via policy/process.

**Command Executed:**

```
(Manual) Validate SAS creation templates/enforcement
```

**Evidence/Output:**

```
{'policy': 'Not enforced'}
```

---

### 55. Ensure SAS tokens expire within an hour (Manual)
- **Check ID:** `azstor_16.2`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:storage:queue-sas-expiry`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** SAS token expiry practice exceeds 1 hour.

**Recommendation (CIS):** Set SAS expiry <= 1 hour; prefer stored access policies.

**Command Executed:**

```
(Manual) Review SAS issuance configuration
```

**Evidence/Output:**

```
{'defaultExpiryHours': 8}
```

---

### 56. Ensure stored access policies (SAP) are used for SAS (Manual)
- **Check ID:** `azstor_16.3`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:storage:queue-sas-sap`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** SAS issuance does not use stored access policies.

**Recommendation (CIS):** Create and use stored access policies for SAS issuance.

**Command Executed:**

```
(Manual) Review SAS tokens for 'si' parameter
```

**Evidence/Output:**

```
{'storedAccessPolicyUsed': False}
```

---

### 57. Ensure soft delete on Backup vaults is Enabled (Automated)
- **Check ID:** `azstor_5.1.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:backup:backup-vault-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Soft delete is not enabled on Backup vault.

**Recommendation (CIS):** Enable soft delete with appropriate retention (14-180 days).

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'softDeleteSettings': {'state': 'Off', 'retentionDurationInDays': None}}
```

---

### 58. Ensure immutability for Backup vaults is Enabled (Automated)
- **Check ID:** `azstor_5.1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:backup-vault-immutability`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Immutability is not enabled on Backup vault.

**Recommendation (CIS):** Enable and consider locking immutability on Backup vaults.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'immutabilitySettings': {'state': 'Disabled'}}
```

---

### 59. Ensure Backup vaults use customer-managed keys (CMK) (Automated)
- **Check ID:** `azstor_5.1.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:backup-vault-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Backup vault uses Microsoft-managed keys.

**Recommendation (CIS):** Configure CMK and grant vault access to the key in Key Vault.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'securitySettings': {'encryptionSettings': {'keyVaultProperties': None}}}
```

---

### 60. Ensure 'Use infrastructure encryption for this vault' is enabled (Automated)
- **Check ID:** `azstor_5.1.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:backup:backup-vault-infra-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Infrastructure encryption not enabled on Backup vault.

**Recommendation (CIS):** Enable infrastructure encryption alongside CMK.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'securitySettings': {'encryptionSettings': {'infrastructureEncryption': 'Disabled'}}}
```

---

### 61. Ensure 'Cross Subscription Restore' is Disabled on Backup vaults (Automated)
- **Check ID:** `azstor_5.1.6`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `azure:backup:backup-vault-csr`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Cross subscription restore is disabled.

**Recommendation (CIS):** Keep CSR disabled unless absolutely necessary.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'featureSettings': {'crossSubscriptionRestoreSettings': {'state': 'Disabled'}}}
```

---

### 62. Ensure soft delete on Recovery Services vaults is Enabled (Automated)
- **Check ID:** `azstor_5.2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:backup:rsv-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Soft delete is disabled on Recovery Services vault.

**Recommendation (CIS):** Enable soft delete for cloud and hybrid workloads and set retention.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'softDeleteSettings': {'softDeleteState': 'Disabled', 'softDeleteRetentionPeriodInDays': None}}
```

---

### 63. Ensure immutability for Recovery Services vaults is Enabled (Automated)
- **Check ID:** `azstor_5.2.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:rsv-immutability`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Immutability is not enabled on Recovery Services vault.

**Recommendation (CIS):** Enable and consider locking immutability on Recovery Services vaults.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'immutabilitySettings': {'state': 'Disabled'}}
```

---

### 64. Ensure Recovery Services vaults use customer-managed keys (CMK) (Automated)
- **Check ID:** `azstor_5.2.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:rsv-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Recovery Services vault uses Microsoft-managed keys.

**Recommendation (CIS):** Configure CMK for the Recovery Services vault and assign permissions.

**Command Executed:**

```
az backup vault encryption show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'properties': {'encryptionAtRestType': 'MicrosoftManaged'}}
```

---

### 65. Ensure public network access on Recovery Services vaults is Disabled (Automated)
- **Check ID:** `azstor_5.2.5`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:backup:rsv-pna`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Public network access is enabled on Recovery Services vault.

**Recommendation (CIS):** Disable public network access and use private endpoints.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV> --query properties.publicNetworkAccess
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---

### 66. Ensure 'Public network access' is 'Disabled' on Azure Elastic SAN (Automated)
- **Check ID:** `azstor_15.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:elasticsan:public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Elastic SAN allows public network access.

**Recommendation (CIS):** Disable public network access on Elastic SAN.

**Command Executed:**

```
az elastic-san show --resource-group <RG> --name <ELASTICSAN> --query publicNetworkAccess
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---

### 67. Ensure CMK is used to encrypt data at rest on Elastic SAN volume groups (Automated)
- **Check ID:** `azstor_15.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:elasticsan:vg-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Elastic SAN volume group not using customer-managed keys.

**Recommendation (CIS):** Assign identity and configure CMK for volume groups.

**Command Executed:**

```
az elastic-san volume-group show --resource-group <RG> --elastic-san <ELASTICSAN> --volume-group <VG>
```

**Evidence/Output:**

```
{'encryption': 'EncryptionAtRestWithPlatformKey'}
```

---

### 68. Ensure 'Encryption key source' is 'Customer Managed Key' for Azure NetApp Files (Automated)
- **Check ID:** `azstor_10.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:anf:cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Azure NetApp Files account is not configured with CMK.

**Recommendation (CIS):** Configure Customer Managed Key via Key Vault for ANF accounts.

**Command Executed:**

```
az netappfiles account show --resource-group <RG> --account-name <ANF_ACCOUNT> --query encryption.keySource
```

**Evidence/Output:**

```
{'keySource': 'Microsoft.NetApp'}
```

---

### 69. Ensure soft delete on Backup vaults is Enabled (Automated)
- **Check ID:** `azstor_5.1.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:backup:vault-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Backup vault soft delete is disabled or retention not set.

**Recommendation (CIS):** Enable soft delete and set retention between 14 and 180 days.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'softDeleteSettings': {'state': 'Off', 'retentionDurationInDays': None}}
```

---

### 70. Ensure immutability for Backup vaults is Enabled (Automated)
- **Check ID:** `azstor_5.1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:vault-immutability`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Backup vault immutability is not enabled/locked.

**Recommendation (CIS):** Enable and lock immutability on Backup vaults where appropriate.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'immutabilitySettings': {'state': 'Disabled'}}
```

---

### 71. Ensure backup data in Backup vaults uses CMK (Automated)
- **Check ID:** `azstor_5.1.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:backup:vault-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Backup vault not configured with customer-managed keys.

**Recommendation (CIS):** Configure CMK with proper identity and Key Vault permissions.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.securitySettings.encryptionSettings
```

**Evidence/Output:**

```
{'keyVaultProperties': None}
```

---

### 72. Ensure 'Use infrastructure encryption for this vault' is enabled (Automated)
- **Check ID:** `azstor_5.1.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:backup:vault-infra-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Infrastructure encryption not enabled on Backup vault.

**Recommendation (CIS):** Enable infrastructure encryption in conjunction with CMK.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT>
```

**Evidence/Output:**

```
{'infrastructureEncryption': 'Disabled'}
```

---

### 73. Ensure 'Cross Region Restore' is 'Enabled' on Backup vaults (Automated)
- **Check ID:** `azstor_5.1.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:backup:vault-crr`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Cross Region Restore is disabled on Backup vault.

**Recommendation (CIS):** Enable CRR if aligned with DR strategy and redundancy type.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.featureSettings.crossRegionRestoreSettings.state
```

**Evidence/Output:**

```
{'crossRegionRestore': 'Disabled'}
```

---

### 74. Ensure 'Cross Subscription Restore' is 'Disabled' or 'Permanently Disabled' (Automated)
- **Check ID:** `azstor_5.1.6`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `azure:backup:vault-csr`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Cross Subscription Restore is enabled increasing data exposure risk.

**Recommendation (CIS):** Disable or permanently disable cross subscription restore.

**Command Executed:**

```
az dataprotection backup-vault show --resource-group <RG> --vault-name <VAULT> --query properties.featureSettings.crossSubscriptionRestoreSettings.state
```

**Evidence/Output:**

```
{'crossSubscriptionRestore': 'Enabled'}
```

---

### 75. Ensure soft delete on Recovery Services vaults is Enabled (Automated)
- **Check ID:** `azstor_5.2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:rsv:vault-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Recovery Services vault soft delete and security features not enabled.

**Recommendation (CIS):** Enable soft delete for cloud and hybrid workloads and set retention 14-180 days.

**Command Executed:**

```
az backup vault backup-properties show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'softDeleteFeatureState': 'Disable', 'softDeleteDuration': None, 'hybridBackupSecurityFeatures': 'Disable'}
```

---

### 76. Ensure immutability for Recovery Services vaults is Enabled (Automated)
- **Check ID:** `azstor_5.2.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:rsv:vault-immutability`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Recovery Services vault immutability is not enabled/locked.

**Recommendation (CIS):** Enable and lock immutability on Recovery Services vaults as appropriate.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'immutabilitySettings': {'state': 'Disabled'}}
```

---

### 77. Ensure backup data in RSV uses CMK (Automated)
- **Check ID:** `azstor_5.2.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:rsv:vault-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Recovery Services vault not configured with customer-managed key.

**Recommendation (CIS):** Configure CMK with proper identity and Key Vault permissions for RSV.

**Command Executed:**

```
az backup vault encryption show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'encryptionAtRestType': 'MicrosoftManaged', 'keyUri': None}
```

---

### 78. Ensure 'Use infrastructure encryption for this vault' is enabled on RSV (Automated)
- **Check ID:** `azstor_5.2.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:rsv:vault-infra-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Infrastructure encryption not enabled on Recovery Services vault.

**Recommendation (CIS):** Enable infrastructure encryption with CMK for RSV.

**Command Executed:**

```
az backup vault encryption show --resource-group <RG> --name <RSV>
```

**Evidence/Output:**

```
{'infrastructureEncryptionState': 'Disabled'}
```

---

### 79. Ensure public network access on Recovery Services vaults is Disabled (Automated)
- **Check ID:** `azstor_5.2.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:rsv:vault-public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Recovery Services vault allows public network access.

**Recommendation (CIS):** Disable public network access and use private endpoints where supported.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV> --query properties.publicNetworkAccess
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---

### 80. Ensure 'Cross Region Restore' is 'Enabled' on RSV (Automated)
- **Check ID:** `azstor_5.2.6`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:rsv:vault-crr`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Cross Region Restore is disabled on Recovery Services vault.

**Recommendation (CIS):** Enable CRR if aligned with DR strategy and redundancy.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV> --query properties.redundancySettings.crossRegionRestore
```

**Evidence/Output:**

```
{'crossRegionRestore': 'Disabled'}
```

---

### 81. Ensure 'Cross Subscription Restore' is 'Disabled' or 'Permanently Disabled' on RSV (Automated)
- **Check ID:** `azstor_5.2.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `azure:rsv:vault-csr`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** RSV Cross Subscription Restore is enabled increasing data exposure risk.

**Recommendation (CIS):** Disable or permanently disable cross subscription restore on RSV.

**Command Executed:**

```
az backup vault show --resource-group <RG> --name <RSV> --query properties.restoreSettings.crossSubscriptionRestoreSettings.crossSubscriptionRestoreState
```

**Evidence/Output:**

```
{'crossSubscriptionRestoreState': 'Enabled'}
```

---

### 82. Ensure 'Public network access' is set to 'Disabled' on Azure Elastic SAN (Automated)
- **Check ID:** `azstor_15.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:elasticsan:public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Elastic SAN public network access is enabled.

**Recommendation (CIS):** Disable public network access at the SAN level.

**Command Executed:**

```
az elastic-san show --resource-group <RG> --name <ELASTIC_SAN> --query publicNetworkAccess
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---

### 83. Ensure CMK is used to encrypt data at rest on Elastic SAN volume groups (Automated)
- **Check ID:** `azstor_15.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:elasticsan:vg-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** Elastic SAN volume group not configured for CMK encryption.

**Recommendation (CIS):** Configure EncryptionAtRestWithCustomerManagedKey with proper Key Vault settings.

**Command Executed:**

```
az elastic-san volume-group show --resource-group <RG> --elastic-san <ELASTIC_SAN> --name <VG> --query encryption
```

**Evidence/Output:**

```
{'encryption': 'EncryptionAtRestWithPlatformKey'}
```

---

### 84. Ensure 'Encryption key source' is 'Customer Managed Key' for Azure NetApp Files accounts (Automated)
- **Check ID:** `azstor_10.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:anf:account-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Storage Services Benchmark v1.0.0

**Description:** NetApp Files account uses platform-managed encryption keys.

**Recommendation (CIS):** Switch Encryption key source to Customer Managed Key and select CMK in Key Vault.

**Command Executed:**

```
az netappfiles account show --resource-group <RG> --account-name <ANF> --query encryption.keySource
```

**Evidence/Output:**

```
{'keySource': 'Microsoft.NetApp'}
```

---

### 85. Cosmos DB: Use selected networks (not all) (Automated)
- **Check ID:** `azdb_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:cosmosdb:network-selected-networks`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** Cosmos DB allows access from all networks.

**Recommendation (CIS):** Set Public network access to Selected networks and configure VNets.

**Command Executed:**

```
az cosmosdb show --name <ACCOUNT> --resource-group <RG> --query 'isVirtualNetworkFilterEnabled'
```

**Evidence/Output:**

```
{'isVirtualNetworkFilterEnabled': False}
```

---

### 86. Cosmos DB: Private endpoints are used (Automated)
- **Check ID:** `azdb_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:cosmosdb:private-endpoints`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** No private endpoint configured for Cosmos DB.

**Recommendation (CIS):** Create a Private Endpoint with Approved connection state.

**Command Executed:**

```
az network private-endpoint-connection list --id $(az cosmosdb show --name <ACCOUNT> --resource-group <RG> --query id -o tsv)
```

**Evidence/Output:**

```
{'privateEndpoints': []}
```

---

### 87. MySQL: Enforce SSL connection is Enabled (Automated)
- **Check ID:** `azdb_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:mysql:enforce-ssl`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** MySQL server does not enforce SSL connections.

**Recommendation (CIS):** Enable Enforce SSL connection on the MySQL server.

**Command Executed:**

```
az mysql server show --resource-group <RG> --name <SERVER> --query sslEnforcement
```

**Evidence/Output:**

```
{'sslEnforcement': 'Disabled'}
```

---

### 88. MySQL Flexible: TLS version set to TLS1.2+ (Automated)
- **Check ID:** `azdb_6.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:mysql:flexible-tls-version`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** MySQL flexible server allows TLS versions lower than 1.2.

**Recommendation (CIS):** Set server parameter tls_version to TLSV1.2 or higher.

**Command Executed:**

```
az mysql flexible-server parameter show --name tls_version --resource-group <RG> --server-name <SERVER>
```

**Evidence/Output:**

```
{'value': 'TLSv1'}
```

---

### 89. MySQL: audit_log_enabled is ON (Manual)
- **Check ID:** `azdb_6.3`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:mysql:audit-log-enabled`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** MySQL audit logging is not enabled.

**Recommendation (CIS):** Set audit_log_enabled ON and configure diagnostic settings.

**Command Executed:**

```
(Portal) Server parameters -> audit_log_enabled
```

**Evidence/Output:**

```
{'audit_log_enabled': 'OFF'}
```

---

### 90. PostgreSQL: Enforce SSL connection Enabled (Automated)
- **Check ID:** `azdb_7.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:postgres:enforce-ssl`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** PostgreSQL server does not enforce SSL connections.

**Recommendation (CIS):** Enable Enforce SSL connection.

**Command Executed:**

```
az postgres server show --resource-group <RG> --name <SERVER> --query sslEnforcement
```

**Evidence/Output:**

```
{'sslEnforcement': 'Disabled'}
```

---

### 91. PostgreSQL: log_checkpoints ON (Automated)
- **Check ID:** `azdb_7.2`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:postgres:log_checkpoints`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** log_checkpoints is not enabled.

**Recommendation (CIS):** Set log_checkpoints to ON.

**Command Executed:**

```
az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_checkpoints
```

**Evidence/Output:**

```
{'value': 'off'}
```

---

### 92. PostgreSQL: log_connections ON (Automated)
- **Check ID:** `azdb_7.3`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:postgres:log_connections`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** log_connections is not enabled.

**Recommendation (CIS):** Set log_connections to ON.

**Command Executed:**

```
az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_connections
```

**Evidence/Output:**

```
{'value': 'off'}
```

---

### 93. PostgreSQL: log_disconnections ON (Automated)
- **Check ID:** `azdb_7.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:postgres:log_disconnections`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** log_disconnections is not enabled.

**Recommendation (CIS):** Set log_disconnections to ON.

**Command Executed:**

```
az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_disconnections
```

**Evidence/Output:**

```
{'value': 'off'}
```

---

### 94. PostgreSQL: connection_throttling ON (Automated)
- **Check ID:** `azdb_7.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:postgres:connection_throttling`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** connection_throttling is not enabled.

**Recommendation (CIS):** Set connection_throttling to ON.

**Command Executed:**

```
az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name connection_throttling
```

**Evidence/Output:**

```
{'value': 'off'}
```

---

### 95. PostgreSQL: log_retention_days > 3 (Automated)
- **Check ID:** `azdb_7.6`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:postgres:log_retention_days`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** log_retention_days set too low.

**Recommendation (CIS):** Set log_retention_days between 4 and 7 inclusive.

**Command Executed:**

```
az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_retention_days
```

**Evidence/Output:**

```
{'value': '3'}
```

---

### 96. PostgreSQL: 'Allow access to Azure services' disabled (Automated)
- **Check ID:** `azdb_7.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `azure:postgres:allow-azure-services`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** Firewall rule AllowAllWindowsAzureIps is present.

**Recommendation (CIS):** Remove AllowAllWindowsAzureIps and define specific firewall/VNet rules.

**Command Executed:**

```
az postgres server firewall-rule list --resource-group <RG> --server-name <SERVER>
```

**Evidence/Output:**

```
{'rules': [{'name': 'AllowAllWindowsAzureIps', 'startIpAddress': '0.0.0.0', 'endIpAddress': '0.0.0.0'}]}
```

---

### 97. SQL: Server auditing is On (Automated)
- **Check ID:** `azdb_10.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:sql:server-auditing`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** SQL Server auditing is not enabled.

**Recommendation (CIS):** Enable auditing to Log Analytics/Event Hub/Storage with retention.

**Command Executed:**

```
(Portal/PowerShell) Get-AzSqlServerAudit
```

**Evidence/Output:**

```
{'auditing': 'Disabled'}
```

---

### 98. SQL: No ingress from 0.0.0.0/0 (Automated)
- **Check ID:** `azdb_10.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:sql:server-firewall-any`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** SQL server firewall permits any IP or 'AllowAllWindowsAzureIps'.

**Recommendation (CIS):** Remove broad rules and configure specific IP ranges only.

**Command Executed:**

```
az sql server firewall-rule list --resource-group <RG> --server <SERVER>
```

**Evidence/Output:**

```
{'rules': [{'name': 'AllowAllWindowsAzureIps'}, {'startIpAddress': '0.0.0.0', 'endIpAddress': '255.255.255.255'}]}
```

---

### 99. SQL: TDE protector uses Customer-managed key (Automated)
- **Check ID:** `azdb_10.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:sql:tde-cmk`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** SQL Server TDE protector not configured with CMK in Key Vault.

**Recommendation (CIS):** Configure server TDE protector with Azure Key Vault CMK.

**Command Executed:**

```
az sql server tde-key show --resource-group <RG> --server <SERVER>
```

**Evidence/Output:**

```
{'serverKeyType': 'ServiceManaged'}
```

---

### 100. SQL: Entra authentication configured (Automated)
- **Check ID:** `azdb_10.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:sql:entra-admin`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** No Entra admin configured for SQL Server.

**Recommendation (CIS):** Set a Microsoft Entra admin for SQL Server.

**Command Executed:**

```
az sql server ad-admin list --resource-group <RG> --server <SERVER>
```

**Evidence/Output:**

```
{'admins': []}
```

---

### 101. SQL DB: Data encryption (TDE) is On (Automated)
- **Check ID:** `azdb_10.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:sqldb:tde-on`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** Transparent Data Encryption is not enabled on a database.

**Recommendation (CIS):** Enable TDE for all user databases.

**Command Executed:**

```
az sql db tde show --resource-group <RG> --server <SERVER> --database <DB> --query status
```

**Evidence/Output:**

```
{'status': 'Disabled'}
```

---

### 102. SQL: Auditing retention > 90 days (Automated)
- **Check ID:** `azdb_10.6`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:sql:auditing-retention`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** Auditing retention less than 90 days or disabled.

**Recommendation (CIS):** Set auditing retention to 90+ days or unlimited.

**Command Executed:**

```
(PowerShell) Get-AzSqlServerAudit | Select RetentionInDays
```

**Evidence/Output:**

```
{'RetentionInDays': 30}
```

---

### 103. SQL: Public Network Access is Disabled (Manual)
- **Check ID:** `azdb_10.7`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:sql:public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Database Services Benchmark v1.0.0

**Description:** SQL server public network access is enabled.

**Recommendation (CIS):** Disable Public network access under Networking.

**Command Executed:**

```
(Portal) SQL Server -> Networking -> Public access
```

**Evidence/Output:**

```
{'publicNetworkAccess': 'Enabled'}
```

---