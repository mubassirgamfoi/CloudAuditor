# CloudAuditor Compliance Report

**Generated:** 2025-10-29T19:43:56.920926
**Provider:** GCP
**Project ID:** test-project
**Command:** `cloudauditor scan gcp --profile test-project --output markdown --output-file test_gcp_enhanced_output.md`

## Benchmarks Executed
- CIS Google Cloud Platform Foundation Benchmark v3.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 4
- **Failed:** 499
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

---

### 29. Ensure that IP forwarding is not enabled on the instance (Manual)
- **Check ID:** `vm_4.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `gcp:vm:ip-forwarding`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** IP forwarding is enabled on the instance.

**Recommendation (CIS):** Disable IP forwarding on the instance unless required.

---

### 30. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 31. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 32. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 33. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 34. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 35. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 36. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 37. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 38. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 39. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 40. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 41. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 42. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 43. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 44. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 45. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 46. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 47. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 48. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 49. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 50. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 51. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 52. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 53. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 54. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 55. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 56. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 57. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 58. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 59. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 60. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 61. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 62. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 63. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 64. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 65. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 66. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 67. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 68. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 69. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 70. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 71. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 72. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 73. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 74. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 75. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 76. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 77. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 78. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 79. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 80. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 81. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 82. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 83. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 84. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 85. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 86. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 87. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 88. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 89. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 90. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 91. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 92. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 93. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 94. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 95. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 96. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 97. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 98. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 99. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 100. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 101. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 102. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 103. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 104. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 105. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 106. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 107. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 108. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 109. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 110. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 111. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 112. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 113. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 114. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 115. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 116. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 117. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 118. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 119. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 120. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 121. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 122. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 123. Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Manual)
- **Check ID:** `vm_4.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:vm:default-service-account-full-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Instances are configured to use the default service account with full access to all Cloud APIs.

**Recommendation (CIS):** Remove full access to all Cloud APIs from the default service account.

---

### 124. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 125. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 126. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 127. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 128. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 129. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 130. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 131. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 132. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 133. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 134. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 135. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 136. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 137. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 138. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 139. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 140. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 141. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 142. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 143. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 144. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 145. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 146. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 147. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 148. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 149. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 150. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 151. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 152. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 153. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 154. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 155. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 156. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 157. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 158. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 159. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 160. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 161. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 162. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 163. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 164. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 165. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 166. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 167. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 168. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 169. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 170. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 171. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 172. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 173. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 174. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 175. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 176. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 177. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 178. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 179. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 180. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 181. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 182. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 183. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 184. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 185. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 186. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 187. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 188. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 189. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 190. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 191. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 192. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 193. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 194. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 195. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 196. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 197. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 198. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 199. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 200. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 201. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 202. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 203. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 204. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 205. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 206. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 207. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 208. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 209. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 210. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 211. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 212. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 213. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 214. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 215. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 216. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 217. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 218. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 219. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-96`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 220. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-97`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 221. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-98`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 222. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-99`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 223. Ensure that Cloud Storage bucket is not publicly accessible (Manual)
- **Check ID:** `storage_5.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:storage:bucket-public-access-100`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud Storage bucket is publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud Storage bucket.

---

### 224. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 225. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 226. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 227. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 228. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 229. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 230. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 231. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 232. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 233. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 234. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 235. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 236. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 237. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 238. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 239. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 240. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 241. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 242. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 243. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 244. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 245. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 246. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 247. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 248. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 249. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 250. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 251. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 252. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 253. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 254. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 255. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 256. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 257. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 258. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 259. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 260. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 261. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 262. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 263. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 264. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 265. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 266. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 267. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 268. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 269. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 270. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 271. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 272. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 273. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 274. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 275. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 276. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 277. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 278. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 279. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 280. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 281. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 282. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 283. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 284. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 285. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 286. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 287. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 288. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 289. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 290. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 291. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 292. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 293. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 294. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 295. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 296. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 297. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 298. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 299. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 300. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 301. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 302. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 303. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 304. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 305. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 306. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 307. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 308. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 309. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 310. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 311. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 312. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 313. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 314. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 315. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 316. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 317. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 318. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 319. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-96`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 320. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-97`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 321. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-98`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 322. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-99`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 323. Ensure that Cloud SQL database instances are not publicly accessible (Manual)
- **Check ID:** `cloudsql_6.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:cloudsql:public-access-100`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Cloud SQL database instances are publicly accessible.

**Recommendation (CIS):** Remove public access from Cloud SQL database instances.

---

### 324. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 325. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 326. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 327. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 328. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 329. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 330. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 331. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 332. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 333. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 334. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 335. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 336. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 337. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 338. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 339. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 340. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 341. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 342. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 343. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 344. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 345. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 346. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 347. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 348. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 349. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 350. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 351. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 352. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 353. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 354. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 355. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 356. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 357. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 358. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 359. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 360. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 361. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 362. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 363. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 364. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 365. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 366. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 367. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 368. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 369. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 370. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 371. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 372. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 373. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 374. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 375. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 376. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 377. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 378. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 379. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 380. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 381. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 382. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 383. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 384. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 385. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 386. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 387. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 388. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 389. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 390. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 391. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 392. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 393. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 394. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 395. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 396. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 397. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 398. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 399. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 400. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 401. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 402. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 403. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 404. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 405. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 406. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 407. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 408. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 409. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 410. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 411. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 412. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 413. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 414. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 415. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 416. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 417. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 418. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 419. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-96`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 420. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-97`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 421. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-98`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 422. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-99`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 423. Ensure that BigQuery datasets are not publicly accessible (Manual)
- **Check ID:** `bigquery_7.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:bigquery:dataset-public-access-100`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** BigQuery datasets are publicly accessible.

**Recommendation (CIS):** Remove public access from BigQuery datasets.

---

### 424. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 425. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-2`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 426. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-3`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 427. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-4`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 428. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-5`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 429. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-6`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 430. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-7`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 431. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-8`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 432. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-9`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 433. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.10`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-10`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 434. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-11`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 435. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.12`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-12`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 436. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.13`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-13`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 437. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.14`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-14`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 438. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-15`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 439. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.16`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-16`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 440. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.17`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-17`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 441. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.18`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-18`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 442. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.19`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-19`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 443. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.20`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-20`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 444. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.21`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-21`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 445. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.22`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-22`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 446. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.23`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-23`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 447. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.24`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-24`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 448. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.25`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-25`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 449. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.26`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-26`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 450. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.27`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-27`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 451. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.28`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-28`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 452. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.29`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-29`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 453. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.30`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-30`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 454. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.31`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-31`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 455. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.32`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-32`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 456. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.33`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-33`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 457. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.34`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-34`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 458. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.35`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-35`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 459. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.36`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-36`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 460. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.37`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-37`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 461. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.38`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-38`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 462. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.39`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-39`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 463. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.40`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-40`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 464. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.41`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-41`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 465. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.42`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-42`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 466. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.43`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-43`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 467. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.44`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-44`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 468. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.45`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-45`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 469. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.46`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-46`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 470. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.47`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-47`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 471. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.48`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-48`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 472. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.49`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-49`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 473. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.50`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-50`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 474. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.51`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-51`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 475. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.52`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-52`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 476. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.53`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-53`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 477. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.54`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-54`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 478. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.55`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-55`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 479. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.56`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-56`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 480. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.57`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-57`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 481. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.58`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-58`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 482. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.59`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-59`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 483. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.60`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-60`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 484. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.61`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-61`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 485. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.62`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-62`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 486. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.63`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-63`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 487. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.64`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-64`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 488. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.65`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-65`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 489. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.66`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-66`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 490. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.67`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-67`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 491. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.68`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-68`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 492. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.69`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-69`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 493. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.70`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-70`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 494. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.71`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-71`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 495. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.72`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-72`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 496. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.73`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-73`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 497. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.74`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-74`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 498. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.75`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-75`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 499. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.76`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-76`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 500. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.77`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-77`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 501. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.78`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-78`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 502. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.79`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-79`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 503. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.80`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-80`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 504. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.81`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-81`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 505. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.82`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-82`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 506. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.83`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-83`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 507. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.84`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-84`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 508. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.85`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-85`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 509. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.86`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-86`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 510. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.87`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-87`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 511. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.88`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-88`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 512. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.89`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-89`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 513. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.90`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-90`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 514. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.91`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-91`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 515. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.92`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-92`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 516. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.93`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-93`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 517. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.94`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-94`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 518. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.95`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-95`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 519. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.96`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-96`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 520. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.97`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-97`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 521. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.98`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-98`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 522. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.99`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-99`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---

### 523. Ensure that Dataproc clusters are not publicly accessible (Manual)
- **Check ID:** `dataproc_8.100`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `gcp:dataproc:cluster-public-access-100`
- **Region:** global
- **Compliance:** CIS Google Cloud Platform Foundation Benchmark v3.0.0

**Description:** Dataproc clusters are publicly accessible.

**Recommendation (CIS):** Remove public access from Dataproc clusters.

---