# CloudAuditor Compliance Report

**Generated:** 2025-10-29T20:11:09.913575
**Provider:** GCP
**Project ID:** test-project
**Command:** `cloudauditor scan gcp --profile test-project --output markdown --output-file test_gcp_final_fixed_output.md`

## Benchmarks Executed
- CIS Google Cloud Platform Foundation Benchmark v3.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 4
- **Failed:** 9
- **Warnings:** 0

## Findings

### 1. Ensure that corporate login credentials are configured (Manual)
- **Check ID:** `iam_1.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:iam:corporate-login`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Corporate login credentials are not properly configured.

**Recommendation (CIS):** Configure corporate login credentials for centralized identity management.

**Command Executed:**

```
gcloud organizations list --format='value(name,displayName)'
```

**Evidence/Output:**

```
{'corporateLoginConfigured': False}
```

---

### 2. Ensure that multi-factor authentication is enabled for all non-service accounts (Manual)
- **Check ID:** `iam_1.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:iam:mfa`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Multi-factor authentication is not enabled for all non-service accounts.

**Recommendation (CIS):** Enable multi-factor authentication for all non-service accounts.

**Command Executed:**

```
gcloud iam policies get-iam-policy PROJECT_ID --format=json
```

**Evidence/Output:**

```
{'mfaEnabled': False, 'nonServiceAccounts': 5}
```

---

### 3. Ensure that User-Managed Service Account Keys are Rotated (Manual)
- **Check ID:** `iam_1.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:iam:service-account-keys`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** User-managed service account keys are not being rotated regularly.

**Recommendation (CIS):** Implement regular rotation of user-managed service account keys.

**Command Executed:**

```
gcloud iam service-accounts keys list --iam-account=SERVICE_ACCOUNT_EMAIL --format=json
```

**Evidence/Output:**

```
{'keysRotated': False, 'oldestKeyAge': 120}
```

---

### 4. Ensure that Separation of Duties is Enforced While Assigning Service Account Related Roles to Users (Manual)
- **Check ID:** `iam_1.4`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `gcp:iam:separation-of-duties`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is properly enforced for service account roles.

**Recommendation (CIS):** Continue monitoring separation of duties for service account roles.

**Command Executed:**

```
gcloud iam roles list --filter='title:Service Account' --format=json
```

**Evidence/Output:**

```
{'separationOfDutiesEnforced': True}
```

---

### 5. Ensure that Cloud KMS is Used to Encrypt Secrets in GCP (Manual)
- **Check ID:** `iam_1.5`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:iam:kms-encryption`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud KMS is not being used to encrypt secrets in GCP.

**Recommendation (CIS):** Use Cloud KMS to encrypt secrets in GCP.

**Command Executed:**

```
gcloud kms keyrings list --location=global --format=json
```

**Evidence/Output:**

```
{'kmsKeyRings': [], 'secretsEncrypted': False}
```

---

### 6. Ensure that Separation of Duties is Enforced While Assigning KMS Related Roles to Users (Manual)
- **Check ID:** `iam_1.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:iam:kms-separation-of-duties`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is not properly enforced for KMS-related roles.

**Recommendation (CIS):** Enforce separation of duties for KMS-related roles.

**Command Executed:**

```
gcloud kms keyrings get-iam-policy KEYRING_NAME --location=LOCATION --format=json
```

**Evidence/Output:**

```
{'kmsSeparationOfDutiesEnforced': False}
```

---

### 7. Ensure that Separation of Duties is Enforced While Assigning Service Account Related Roles to Users (Manual)
- **Check ID:** `iam_1.7`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `gcp:iam:service-account-separation`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is properly enforced for service account roles.

**Recommendation (CIS):** Continue monitoring separation of duties for service account roles.

**Command Executed:**

```
gcloud iam service-accounts get-iam-policy SERVICE_ACCOUNT_EMAIL --format=json
```

**Evidence/Output:**

```
{'serviceAccountSeparationEnforced': True}
```

---

### 8. Ensure that Separation of Duties is Enforced While Assigning KMS Related Roles to Users (Manual)
- **Check ID:** `iam_1.8`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:iam:kms-role-separation`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is not properly enforced for KMS-related roles.

**Recommendation (CIS):** Enforce separation of duties for KMS-related roles.

**Command Executed:**

```
gcloud kms keys get-iam-policy KEY_NAME --keyring=KEYRING_NAME --location=LOCATION --format=json
```

**Evidence/Output:**

```
{'kmsRoleSeparationEnforced': False}
```

---

### 9. Ensure that Separation of Duties is Enforced While Assigning Service Account Related Roles to Users (Manual)
- **Check ID:** `iam_1.9`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `gcp:iam:service-account-role-separation`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is properly enforced for service account roles.

**Recommendation (CIS):** Continue monitoring separation of duties for service account roles.

**Command Executed:**

```
gcloud iam roles list --filter='title:Service Account' --format=json
```

**Evidence/Output:**

```
{'serviceAccountRoleSeparationEnforced': True}
```

---

### 10. Ensure that Separation of Duties is Enforced While Assigning KMS Related Roles to Users (Manual)
- **Check ID:** `iam_1.10`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:iam:kms-role-separation-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Separation of duties is not properly enforced for KMS-related roles.

**Recommendation (CIS):** Enforce separation of duties for KMS-related roles.

**Command Executed:**

```
gcloud kms keyrings get-iam-policy KEYRING_NAME --location=LOCATION --format=json
```

**Evidence/Output:**

```
{'kmsRoleSeparation2Enforced': False}
```

---

### 11. Ensure that Cloud Audit Logging is configured to capture all admin activities (Manual)
- **Check ID:** `logging_2.1`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:logging:cloud-audit-logging`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Audit Logging is not configured to capture all admin activities.

**Recommendation (CIS):** Configure Cloud Audit Logging to capture all admin activities.

**Command Executed:**

```
gcloud logging sinks list --format=json
```

**Evidence/Output:**

```
{'adminActivityLogging': False, 'sinksConfigured': 0}
```

---

### 12. Ensure that Cloud Audit Logging is configured to capture all data read events (Manual)
- **Check ID:** `logging_2.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:logging:data-read-events`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Audit Logging is not configured to capture all data read events.

**Recommendation (CIS):** Configure Cloud Audit Logging to capture all data read events.

**Command Executed:**

```
gcloud logging sinks list --filter='name:data-read' --format=json
```

**Evidence/Output:**

```
{'dataReadLogging': False, 'readEventSinks': []}
```

---

### 13. Ensure that Cloud Audit Logging is configured to capture all data write events (Manual)
- **Check ID:** `logging_2.3`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:logging:data-write-events`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Audit Logging is not configured to capture all data write events.

**Recommendation (CIS):** Configure Cloud Audit Logging to capture all data write events.

**Command Executed:**

```
gcloud logging sinks list --filter='name:data-write' --format=json
```

**Evidence/Output:**

```
{'dataWriteLogging': False, 'writeEventSinks': []}
```

---

### 14. Ensure that log sinks are configured to export copies of all log entries (Manual)
- **Check ID:** `logging_2.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:logging:log-sinks`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Log sinks are not configured to export copies of all log entries.

**Recommendation (CIS):** Configure log sinks to export copies of all log entries.

**Command Executed:**

```
gcloud logging sinks list --format=json
```

**Evidence/Output:**

```
{'allLogsExported': False, 'sinkCount': 0}
```

---

### 15. Ensure that log metric filters and alerts exist for project ownership assignments (Manual)
- **Check ID:** `logging_2.5`
- **Severity:** MEDIUM
- **Status:** PASSED
- **Resource:** `gcp:logging:metric-filters`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Log metric filters and alerts are properly configured for project ownership assignments.

**Recommendation (CIS):** Continue monitoring log metric filters and alerts.

**Command Executed:**

```
gcloud logging metrics list --format=json
```

**Evidence/Output:**

```
{'ownershipAssignmentAlerts': True, 'metricFilters': 3}
```

---

### 16. Ensure that the default network does not exist in a project (Manual)
- **Check ID:** `networking_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:networking:default-network`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** The default network still exists in the project.

**Recommendation (CIS):** Delete the default network to prevent unauthorized access.

---

### 17. Ensure that legacy networks do not exist in a project (Manual)
- **Check ID:** `networking_3.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:networking:legacy-networks`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Legacy networks still exist in the project.

**Recommendation (CIS):** Migrate from legacy networks to VPC networks.

---

### 18. Ensure that DNSSEC is enabled for Cloud DNS (Manual)
- **Check ID:** `networking_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:networking:dnssec`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** DNSSEC is not enabled for Cloud DNS.

**Recommendation (CIS):** Enable DNSSEC for Cloud DNS to prevent DNS spoofing attacks.

---

### 19. Ensure that SSH access is restricted from the Internet (Manual)
- **Check ID:** `networking_3.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:networking:ssh-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** SSH access is not properly restricted from the Internet.

**Recommendation (CIS):** Restrict SSH access from the Internet using firewall rules.

---

### 20. Ensure that RDP access is restricted from the Internet (Manual)
- **Check ID:** `networking_3.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:networking:rdp-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** RDP access is not properly restricted from the Internet.

**Recommendation (CIS):** Restrict RDP access from the Internet using firewall rules.

---

### 21. Ensure that VPC Flow Logs are enabled for every subnet (Manual)
- **Check ID:** `networking_3.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:networking:vpc-flow-logs`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** VPC Flow Logs are not enabled for all subnets.

**Recommendation (CIS):** Enable VPC Flow Logs for all subnets to monitor network traffic.

---

### 22. Ensure that SSL policies are not overly permissive (Manual)
- **Check ID:** `networking_3.7`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:networking:ssl-policies`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** SSL policies are overly permissive.

**Recommendation (CIS):** Configure SSL policies to use secure cipher suites and protocols.

---

### 23. Ensure that Identity-Aware Proxy is enabled for App Engine (Manual)
- **Check ID:** `networking_3.8`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:networking:identity-aware-proxy`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Identity-Aware Proxy is not enabled for App Engine.

**Recommendation (CIS):** Enable Identity-Aware Proxy for App Engine applications.

---

### 24. Ensure that instances are not configured to use the default service account (Manual)
- **Check ID:** `vm_4.1`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:vm:default-service-account`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account.

**Recommendation (CIS):** Configure instances to use custom service accounts instead of the default service account.

**Command Executed:**

```
gcloud compute instances list --format='value(name,serviceAccounts[].email)'
```

**Evidence/Output:**

```
{'UsingDefaultServiceAccount': True, 'ServiceAccountEmail': '123456789012-compute@developer.gserviceaccount.com'}
```

---

### 25. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

**Command Executed:**

```
gcloud projects get-iam-policy PROJECT_ID --flatten='bindings[].members' --format='table(bindings.role)' --filter='bindings.members:123456789012-compute@developer.gserviceaccount.com'
```

**Evidence/Output:**

```
{'HasFullAccess': True, 'Roles': ['roles/editor', 'roles/owner'], 'ServiceAccount': '123456789012-compute@developer.gserviceaccount.com'}
```

---

### 26. Ensure that project-wide SSH keys are not used (Manual)
- **Check ID:** `vm_4.3`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `gcp:vm:project-wide-ssh-keys`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Project-wide SSH keys are being used.

**Recommendation (CIS):** Remove project-wide SSH keys and use instance-specific SSH keys instead.

**Command Executed:**

```
gcloud compute project-info describe --format='value(commonInstanceMetadata.items[?key==`ssh-keys`].value)'
```

**Evidence/Output:**

```
{'ProjectWideSSHKeys': True, 'SSHKeyCount': 3, 'Keys': ['ssh-rsa AAAAB3NzaC1yc2E...', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...']}
```

---

### 27. Ensure that OS Login is enabled for a project (Manual)
- **Check ID:** `vm_4.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:vm:os-login`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** OS Login is not enabled for the project.

**Recommendation (CIS):** Enable OS Login for the project to improve security.

**Command Executed:**

```
gcloud compute project-info describe --format='value(commonInstanceMetadata.items[?key==`enable-oslogin`].value)'
```

**Evidence/Output:**

```
{'OSLoginEnabled': False, 'MetadataValue': 'FALSE'}
```

---

### 28. Ensure that the serial port access to VM instances is disabled (Manual)
- **Check ID:** `vm_4.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:vm:serial-port-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Serial port access to VM instances is not disabled.

**Recommendation (CIS):** Disable serial port access to VM instances.

**Command Executed:**

```
gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format='value(metadata.items[?key==`serial-port-enable`].value)'
```

**Evidence/Output:**

```
{'SerialPortEnabled': True, 'MetadataValue': 'TRUE'}
```

---

### 29. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

**Command Executed:**

```
gsutil iam get gs://my-public-bucket
```

**Evidence/Output:**

```
{'PublicAccess': True, 'IamPolicy': {'bindings': [{'role': 'roles/storage.objectViewer', 'members': ['allUsers']}]}}
```

---

### 30. Ensure that uniform bucket-level access is enabled on Cloud Storage buckets (Manual)
- **Check ID:** `storage_5.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:storage:bucket-uniform-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Uniform bucket-level access is not enabled on Cloud Storage bucket.

**Recommendation (CIS):** Enable uniform bucket-level access on Cloud Storage bucket.

**Command Executed:**

```
gsutil uniformbucketlevelaccess get gs://my-bucket
```

**Evidence/Output:**

```
{'UniformBucketLevelAccess': False, 'IamConfiguration': {'uniformBucketLevelAccess': {'enabled': False}}}
```

---

### 31. Ensure that Cloud Storage buckets have encryption enabled (Manual)
- **Check ID:** `storage_5.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:storage:bucket-encryption`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket does not have encryption enabled.

**Recommendation (CIS):** Enable encryption on Cloud Storage bucket.

**Command Executed:**

```
gsutil kms encryption get gs://my-bucket
```

**Evidence/Output:**

```
{'EncryptionEnabled': False, 'DefaultKmsKeyName': None}
```

---

### 32. Ensure that Cloud Storage buckets have logging enabled (Manual)
- **Check ID:** `storage_5.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `gcp:storage:bucket-logging`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket does not have logging enabled.

**Recommendation (CIS):** Enable logging on Cloud Storage bucket.

**Command Executed:**

```
gsutil logging get gs://my-bucket
```

**Evidence/Output:**

```
{'LoggingEnabled': False, 'LogObjectPrefix': None}
```

---

### 33. Ensure that Cloud Storage buckets have versioning enabled (Manual)
- **Check ID:** `storage_5.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `gcp:storage:bucket-versioning`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket does not have versioning enabled.

**Recommendation (CIS):** Enable versioning on Cloud Storage bucket.

**Command Executed:**

```
gsutil versioning get gs://my-bucket
```

**Evidence/Output:**

```
{'VersioningEnabled': False, 'VersioningStatus': 'SUSPENDED'}
```

---

### 34. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_8.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:instance-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instance is publicly accessible.

**Recommendation (CIS):** Configure Cloud SQL instance with private network access.

**Command Executed:**

```
gcloud sql instances describe INSTANCE_NAME --format='value(settings.ipConfiguration.authorizedNetworks[].value)'
```

**Evidence/Output:**

```
{'PublicAccess': True, 'AuthorizedNetworks': ['0.0.0.0/0']}
```

---

### 35. Ensure that Cloud SQL database instances require SSL connections (Manual)
- **Check ID:** `cloudsql_8.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:cloudsql:instance-ssl`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instance does not require SSL connections.

**Recommendation (CIS):** Enable SSL requirement for Cloud SQL instance.

**Command Executed:**

```
gcloud sql instances describe INSTANCE_NAME --format='value(settings.ipConfiguration.requireSsl)'
```

**Evidence/Output:**

```
{'SslRequired': False, 'RequireSsl': False}
```

---

### 36. Ensure that Cloud SQL database instances have automated backups enabled (Manual)
- **Check ID:** `cloudsql_8.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:cloudsql:instance-backups`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instance does not have automated backups enabled.

**Recommendation (CIS):** Enable automated backups for Cloud SQL instance.

**Command Executed:**

```
gcloud sql instances describe INSTANCE_NAME --format='value(settings.backupConfiguration.enabled)'
```

**Evidence/Output:**

```
{'AutomatedBackupsEnabled': False, 'BackupConfiguration': {'enabled': False}}
```

---

### 37. Ensure that Cloud SQL database instances are encrypted (Manual)
- **Check ID:** `cloudsql_8.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:cloudsql:instance-encryption`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instance is not encrypted.

**Recommendation (CIS):** Enable encryption for Cloud SQL instance.

**Command Executed:**

```
gcloud sql instances describe INSTANCE_NAME --format='value(settings.dataDiskType)'
```

**Evidence/Output:**

```
{'EncryptionEnabled': False, 'DataDiskType': 'PD_STANDARD'}
```

---

### 38. Ensure that Cloud SQL database instances have proper network configuration (Manual)
- **Check ID:** `cloudsql_8.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:cloudsql:instance-network`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instance network configuration needs improvement.

**Recommendation (CIS):** Configure proper network settings for Cloud SQL instance.

**Command Executed:**

```
gcloud sql instances describe INSTANCE_NAME --format='value(settings.ipConfiguration)'
```

**Evidence/Output:**

```
{'NetworkConfig': {'ipv4Enabled': True, 'privateNetwork': None}}
```

---

### 39. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery dataset is publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery dataset.

**Command Executed:**

```
bq show --format=prettyjson PROJECT_ID:DATASET_ID
```

**Evidence/Output:**

```
{'PublicAccess': True, 'AccessEntries': [{'role': 'READER', 'userByEmail': 'allUsers'}]}
```

---

### 40. Ensure that BigQuery datasets are encrypted with Customer-Managed Encryption Keys (CMEK) (Manual)
- **Check ID:** `bigquery_6.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:bigquery:dataset-cmek`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery dataset is not encrypted with CMEK.

**Recommendation (CIS):** Enable CMEK encryption for BigQuery dataset.

**Command Executed:**

```
bq show --format=prettyjson PROJECT_ID:DATASET_ID
```

**Evidence/Output:**

```
{'CmekEnabled': False, 'DefaultKmsKeyName': None}
```

---

### 41. Ensure that BigQuery datasets have data classification labels (Manual)
- **Check ID:** `bigquery_6.3`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `gcp:bigquery:dataset-classification`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery dataset does not have data classification labels.

**Recommendation (CIS):** Add data classification labels to BigQuery dataset.

**Command Executed:**

```
bq show --format=prettyjson PROJECT_ID:DATASET_ID
```

**Evidence/Output:**

```
{'Labels': {}, 'ClassificationRequired': True}
```

---

### 42. Ensure that BigQuery query logging is enabled (Manual)
- **Check ID:** `bigquery_6.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:bigquery:query-logging`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery query logging is not enabled.

**Recommendation (CIS):** Enable query logging for BigQuery.

**Command Executed:**

```
gcloud logging sinks list --filter='bigquery.googleapis.com'
```

**Evidence/Output:**

```
{'QueryLoggingEnabled': False, 'LogSinks': []}
```

---

### 43. Ensure that BigQuery audit logging is enabled (Manual)
- **Check ID:** `bigquery_6.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:bigquery:audit-logging`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery audit logging is not enabled.

**Recommendation (CIS):** Enable audit logging for BigQuery.

**Command Executed:**

```
gcloud logging sinks list --filter='bigquery.googleapis.com'
```

**Evidence/Output:**

```
{'AuditLoggingEnabled': False, 'LogSinks': []}
```

---

### 44. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_7.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc cluster is publicly accessible.

**Recommendation (CIS):** Configure Dataproc cluster with private network access.

**Command Executed:**

```
gcloud dataproc clusters describe CLUSTER_NAME --region=REGION
```

**Evidence/Output:**

```
{'PublicAccess': True, 'NetworkConfig': {'enableExternalIp': True}}
```

---

### 45. Ensure that Dataproc clusters are encrypted with Customer-Managed Encryption Keys (CMEK) (Manual)
- **Check ID:** `dataproc_7.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:dataproc:cluster-cmek`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc cluster is not encrypted with CMEK.

**Recommendation (CIS):** Enable CMEK encryption for Dataproc cluster.

**Command Executed:**

```
gcloud dataproc clusters describe CLUSTER_NAME --region=REGION
```

**Evidence/Output:**

```
{'CmekEnabled': False, 'EncryptionConfig': {'gcePdKmsKeyName': None}}
```

---

### 46. Ensure that Dataproc clusters are configured with proper network settings (Manual)
- **Check ID:** `dataproc_7.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:dataproc:cluster-network`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc cluster network configuration needs improvement.

**Recommendation (CIS):** Configure Dataproc cluster with proper network settings.

**Command Executed:**

```
gcloud dataproc clusters describe CLUSTER_NAME --region=REGION
```

**Evidence/Output:**

```
{'NetworkConfig': {'subnetworkUri': 'default', 'enableExternalIp': True}}
```

---

### 47. Ensure that Dataproc clusters use appropriate service accounts (Manual)
- **Check ID:** `dataproc_7.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:dataproc:cluster-service-account`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc cluster is using default service account.

**Recommendation (CIS):** Configure Dataproc cluster with custom service account.

**Command Executed:**

```
gcloud dataproc clusters describe CLUSTER_NAME --region=REGION
```

**Evidence/Output:**

```
{'ServiceAccount': '123456789012-compute@developer.gserviceaccount.com', 'IsDefault': True}
```

---

### 48. Ensure that Dataproc clusters have logging enabled (Manual)
- **Check ID:** `dataproc_7.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `gcp:dataproc:cluster-logging`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc cluster logging is not properly configured.

**Recommendation (CIS):** Enable comprehensive logging for Dataproc cluster.

**Command Executed:**

```
gcloud dataproc clusters describe CLUSTER_NAME --region=REGION
```

**Evidence/Output:**

```
{'LoggingEnabled': False, 'LoggingConfig': {'driverLogLevels': {}}}
```

---