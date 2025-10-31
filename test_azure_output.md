# CloudAuditor Compliance Report

**Generated:** 2025-10-30T00:49:54.715714
**Provider:** AZURE
**Command:** `cloudauditor scan azure --profile test-subscription --output markdown --output-file test_azure_output.md`

## Benchmarks Executed
- CIS Microsoft Azure Foundations Benchmark v5.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 0
- **Failed:** 7
- **Warnings:** 28

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

### 6. Ensure that virtual machines are encrypted (Manual)
- **Check ID:** `compute_2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:compute:vm-encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Virtual machine is not encrypted.

**Recommendation (CIS):** Enable encryption for virtual machine disks.

**Command Executed:**

```
az vm encryption show --name VM_NAME --resource-group RESOURCE_GROUP --query 'status'
```

**Evidence/Output:**

```
{'EncryptionEnabled': False, 'EncryptionStatus': 'NotEncrypted'}
```

---

### 7. Ensure that virtual machines have proper network security group rules (Manual)
- **Check ID:** `compute_2.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:compute:vm-nsg-rules`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Virtual machine has overly permissive network security group rules.

**Recommendation (CIS):** Configure restrictive network security group rules for virtual machines.

**Command Executed:**

```
az network nsg rule list --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --query '[].{Name:name,Access:access,Protocol:protocol,SourcePortRange:sourcePortRange,DestinationPortRange:destinationPortRange,SourceAddressPrefix:sourceAddressPrefix,DestinationAddressPrefix:destinationAddressPrefix}'
```

**Evidence/Output:**

```
{'OverlyPermissiveRules': True, 'Rules': [{'Name': 'AllowRDP', 'Access': 'Allow', 'Protocol': 'Tcp', 'SourcePortRange': '*', 'DestinationPortRange': '3389', 'SourceAddressPrefix': '*', 'DestinationAddressPrefix': '*'}]}
```

---

### 8. Ensure that virtual machines have proper access controls (Manual)
- **Check ID:** `compute_2.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:compute:vm-access-controls`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Virtual machine has insufficient access controls.

**Recommendation (CIS):** Implement proper access controls and role-based access control (RBAC) for virtual machines.

**Command Executed:**

```
az role assignment list --assignee USER_PRINCIPAL_NAME --scope /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/VM_NAME --query '[].{RoleDefinitionName:roleDefinitionName,Scope:scope}'
```

**Evidence/Output:**

```
{'AccessControlsConfigured': False, 'RBACEnabled': False}
```

---

### 9. Ensure that virtual machines have monitoring enabled (Manual)
- **Check ID:** `compute_2.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `azure:compute:vm-monitoring`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Virtual machine does not have comprehensive monitoring enabled.

**Recommendation (CIS):** Enable comprehensive monitoring and logging for virtual machines.

**Command Executed:**

```
az monitor diagnostic-settings list --resource VM_RESOURCE_ID --query '[].{Name:name,Enabled:enabled,Logs:logs}'
```

**Evidence/Output:**

```
{'MonitoringEnabled': False, 'DiagnosticSettings': []}
```

---

### 10. Ensure that virtual machines have proper backup configuration (Manual)
- **Check ID:** `compute_2.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:compute:vm-backup`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Virtual machine does not have proper backup configuration.

**Recommendation (CIS):** Configure automated backup for virtual machines.

**Command Executed:**

```
az backup item list --vault-name VAULT_NAME --resource-group RESOURCE_GROUP --query '[].{Name:name,ProtectionStatus:properties.protectionStatus}'
```

**Evidence/Output:**

```
{'BackupConfigured': False, 'ProtectionStatus': 'NotProtected'}
```

---

### 11. Ensure that security defaults are enabled (Manual)
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

### 12. Ensure that per-user MFA is enabled (Manual)
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

### 13. Ensure that conditional access policies are configured (Manual)
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

### 14. Ensure that periodic identity reviews are configured (Manual)
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

### 15. Ensure that privileged access is properly managed (Manual)
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

### 16. Ensure that diagnostic settings are configured for all resources (Manual)
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

### 17. Ensure that activity log alerts are configured (Manual)
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

### 18. Ensure that Application Insights is enabled (Manual)
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

### 19. Ensure that Azure Monitor resource logging is enabled (Manual)
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

### 20. Ensure that log retention is properly configured (Manual)
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

### 21. Ensure that RDP access is restricted (Manual)
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

### 22. Ensure that SSH access is restricted (Manual)
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

### 23. Ensure that NSG flow logs are enabled (Manual)
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

### 24. Ensure that Network Watcher is enabled (Manual)
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

### 25. Ensure that public IPs are not used unnecessarily (Manual)
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

### 26. Ensure that Microsoft Defender for Cloud is enabled (Manual)
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

### 27. Ensure that Key Vault has proper access controls (Manual)
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

### 28. Ensure that Key Vault has purge protection enabled (Manual)
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

### 29. Ensure that Azure Bastion is configured (Manual)
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

### 30. Ensure that DDoS Network Protection is enabled (Manual)
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

### 31. Ensure that Azure Files has soft delete enabled (Manual)
- **Check ID:** `storage_7.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:azure-files-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Files does not have soft delete enabled.

**Recommendation (CIS):** Enable soft delete for Azure Files to protect against accidental deletion.

**Command Executed:**

```
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query 'azureFilesIdentityBasedAuthentication'
```

**Evidence/Output:**

```
{'SoftDeleteEnabled': False, 'AzureFilesIdentityBasedAuthentication': None}
```

---

### 32. Ensure that Azure Blob Storage has soft delete enabled (Manual)
- **Check ID:** `storage_7.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:azure-blob-soft-delete`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Azure Blob Storage does not have soft delete enabled.

**Recommendation (CIS):** Enable soft delete for Azure Blob Storage to protect against accidental deletion.

**Command Executed:**

```
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query 'blobServices.properties.deleteRetentionPolicy'
```

**Evidence/Output:**

```
{'SoftDeleteEnabled': False, 'DeleteRetentionPolicy': {'Enabled': False}}
```

---

### 33. Ensure that storage accounts have secure transfer enabled (Manual)
- **Check ID:** `storage_7.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `azure:storage:secure-transfer`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Storage accounts do not have secure transfer enabled.

**Recommendation (CIS):** Enable secure transfer for storage accounts to enforce HTTPS.

**Command Executed:**

```
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query 'enableHttpsTrafficOnly'
```

**Evidence/Output:**

```
{'SecureTransferEnabled': False, 'EnableHttpsTrafficOnly': False}
```

---

### 34. Ensure that storage accounts have public network access disabled (Manual)
- **Check ID:** `storage_7.4`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `azure:storage:public-network-access`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Storage accounts have public network access enabled.

**Recommendation (CIS):** Disable public network access for storage accounts to improve security.

**Command Executed:**

```
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query 'publicNetworkAccess'
```

**Evidence/Output:**

```
{'PublicNetworkAccessDisabled': False, 'PublicNetworkAccess': 'Enabled'}
```

---

### 35. Ensure that storage accounts have proper encryption enabled (Manual)
- **Check ID:** `storage_7.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `azure:storage:encryption`
- **Region:** global
- **Compliance:** CIS Microsoft Azure Foundations Benchmark v5.0.0

**Description:** Storage accounts do not have proper encryption enabled.

**Recommendation (CIS):** Enable encryption for storage accounts using customer-managed keys.

**Command Executed:**

```
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query 'encryption'
```

**Evidence/Output:**

```
{'EncryptionEnabled': False, 'Encryption': {'Services': {'Blob': {'Enabled': False}}}}
```

---