# CloudAuditor Compliance Report

**Generated:** 2025-10-29T20:10:12.463688
**Provider:** GCP
**Project ID:** test-project
**Command:** `cloudauditor scan gcp --profile test-project --output markdown --output-file test_gcp_final_output.md`

## Benchmarks Executed
- CIS Google Cloud Platform Foundation Benchmark v3.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 4
- **Failed:** 108
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
- **Check ID:** `cloudsql_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 35. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 36. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 37. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 38. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 39. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 40. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 41. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 42. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 43. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 44. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 45. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 46. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 47. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 48. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 49. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 50. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 51. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 52. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 53. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 54. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 55. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 56. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 57. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 58. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 59. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 60. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 61. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 62. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 63. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 64. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 65. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 66. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 67. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 68. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 69. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 70. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 71. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 72. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 73. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 74. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 75. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 76. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 77. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 78. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 79. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 80. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 81. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 82. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 83. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 84. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 85. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 86. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 87. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 88. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 89. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 90. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 91. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 92. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 93. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 94. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 95. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 96. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 97. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 98. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 99. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 100. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 101. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 102. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 103. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 104. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 105. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 106. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 107. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 108. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 109. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 110. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 111. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 112. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 113. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 114. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 115. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 116. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 117. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 118. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 119. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 120. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 121. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 122. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 123. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 124. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 125. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 126. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 127. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 128. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 129. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-96`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 130. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-97`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 131. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-98`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 132. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-99`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 133. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-100`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 134. Ensure that BigQuery datasets are not publicly accessible (Manual)
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

### 135. Ensure that BigQuery datasets are encrypted with Customer-Managed Encryption Keys (CMEK) (Manual)
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

### 136. Ensure that BigQuery datasets have data classification labels (Manual)
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

### 137. Ensure that BigQuery query logging is enabled (Manual)
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

### 138. Ensure that BigQuery audit logging is enabled (Manual)
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

### 139. Ensure that Dataproc clusters are not publicly accessible (Manual)
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

### 140. Ensure that Dataproc clusters are encrypted with Customer-Managed Encryption Keys (CMEK) (Manual)
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

### 141. Ensure that Dataproc clusters are configured with proper network settings (Manual)
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

### 142. Ensure that Dataproc clusters use appropriate service accounts (Manual)
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

### 143. Ensure that Dataproc clusters have logging enabled (Manual)
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