# CloudAuditor Compliance Report

**Generated:** 2025-10-30T02:35:36.035387
**Provider:** DIGITALOCEAN
**Command:** `cloudauditor scan digitalocean --profile test-team --output markdown --output-file test_do_services.md`

## Benchmarks Executed
- CIS DigitalOcean Foundations Benchmark v1.0.0
- CIS DigitalOcean Services Benchmark v1.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 0
- **Failed:** 7
- **Warnings:** 23

## Findings

### 1. Ensure Secure Sign In for Teams is Enabled (Manual)
- **Check ID:** `do_2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:team:secure-sign-in`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team does not require secure sign-in methods (Google, GitHub, or DO 2FA).

**Recommendation (CIS):** Enable Secure Sign-In in Team Settings.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Secure sign-in
```

**Evidence/Output:**

```
{'secureSignInEnabled': False}
```

---

### 2. Ensure Two Factor Authentication for all Accounts/Teams is Enabled (Manual)
- **Check ID:** `do_2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:account:2fa`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Two-factor authentication is not enabled for all accounts/teams.

**Recommendation (CIS):** Enable 2FA for accounts; enforce secure sign-in for team.

**Command Executed:**

```
(UI) My Account → Two-factor authentication → Set Up 2FA
```

**Evidence/Output:**

```
{'twoFactorEnabled': False}
```

---

### 3. Ensure SSH Keys are Audited (Automated)
- **Check ID:** `do_2.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:account:ssh-keys`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** SSH keys have not been recently reviewed for appropriateness.

**Recommendation (CIS):** Audit SSH keys via Settings → Security → SSH Keys and remove stale keys.

**Command Executed:**

```
doctl compute ssh-key list --format ID,Name,PublicKey,Created
```

**Evidence/Output:**

```
{'keys': [{'id': 123, 'name': 'old-key', 'created': '2021-01-01'}]}
```

---

### 4. Ensure a Distribution List is used as the Team Contact Email (Manual)
- **Check ID:** `do_2.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:team:contact-email`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team contact email is an individual address instead of a distribution list.

**Recommendation (CIS):** Change Team Contact Email to a distribution list.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Team Contact Email → Edit
```

**Evidence/Output:**

```
{'contactEmail': 'owner@example.com', 'isDistributionList': False}
```

---

### 5. Ensure Legacy Tokens are Replaced with Scoped Tokens (Manual)
- **Check ID:** `do_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:api:legacy-tokens`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Legacy tokens detected without fine-grained scopes.

**Recommendation (CIS):** Replace legacy tokens with custom scoped tokens and retire legacy tokens.

**Command Executed:**

```
doctl auth list; curl -H 'Authorization: Bearer $DIGITALOCEAN_TOKEN' https://api.digitalocean.com/v2/tokens
```

**Evidence/Output:**

```
{'legacyTokens': [{'name': 'legacy-rw', 'created_at': '2022-01-01'}]}
```

---

### 6. Ensure Access Tokens Do Not Have Over-Provisioned Scopes (Manual)
- **Check ID:** `do_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:api:overprovisioned-scopes`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** One or more tokens have broader scopes than required.

**Recommendation (CIS):** Review and regenerate tokens with least-privilege scopes.

**Command Executed:**

```
(UI) Control Panel → API → Tokens → Scopes
```

**Evidence/Output:**

```
{'tokens': [{'name': 'ci-token', 'scopes': ['*:']}]}
```

---

### 7. Ensure OAuth and Authorized Third-Party Applications are Appropriate (Automated)
- **Check ID:** `do_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:api:oauth-apps`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Authorized third-party applications require review for appropriateness and scope.

**Recommendation (CIS):** Remove unused or unrecognized OAuth/Authorized applications and limit scopes.

**Command Executed:**

```
(UI) Control Panel → API → OAuth Applications / Authorized Applications
```

**Evidence/Output:**

```
{'authorizedApps': [{'name': 'old-ci-app', 'lastUsed': '2023-01-01'}]}
```

---

### 8. Ensure Role-Based Access Controls are Implemented (Manual)
- **Check ID:** `do_4.1`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `digitalocean:team:rbac`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team roles require review to enforce least privilege.

**Recommendation (CIS):** Use predefined roles (Owner, Member, Biller, Modifier, Billing viewer, Resource viewer) and review assignments.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Team Members
```

**Evidence/Output:**

```
{'members': [{'email': 'dev@example.com', 'role': 'Owner'}]}
```

---

### 9. Ensure Security History is Reviewed Regularly (Manual)
- **Check ID:** `do_5.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:team:security-history`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Security history review cadence is not documented or recent reviews are missing.

**Recommendation (CIS):** Review Security History regularly and document cadence.

**Command Executed:**

```
(UI) Control Panel → Settings → Security
```

**Evidence/Output:**

```
{'lastReview': None}
```

---

### 10. Ensure Backups are Enabled (Manual)
- **Check ID:** `do_svc_2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean/droplet/backups`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Droplet does not have automated backups enabled.

**Recommendation (CIS):** Enable automated backups (daily/weekly) with a defined backup window.

**Command Executed:**

```
doctl compute droplet-action enable-backups <droplet-id> --backup-policy-plan weekly --backup-policy-weekday SUN --backup-policy-hour 4
```

**Evidence/Output:**

```
{'backupsEnabled': False}
```

---

### 11. Ensure a Firewall is Created (Automated)
- **Check ID:** `do_svc_2.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean/firewall/present`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** No DigitalOcean Cloud Firewall defined for the project.

**Recommendation (CIS):** Create a Cloud Firewall with least-privilege inbound/outbound rules.

**Command Executed:**

```
doctl compute firewall create --name example --inbound-rules 'protocol:tcp,ports:22,address:10.0.0.0/8' --outbound-rules 'protocol:tcp,ports:80,address:0.0.0.0/0'
```

**Evidence/Output:**

```
{'firewalls': []}
```

---

### 12. Ensure the Droplet is Connected to a Firewall (Automated)
- **Check ID:** `do_svc_2.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean/droplet/firewall-association`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Droplet is not associated with any Cloud Firewall.

**Recommendation (CIS):** Attach Droplet to an existing Cloud Firewall or tag for policy application.

**Command Executed:**

```
doctl compute firewall add-droplets <firewall-id> --droplet-ids <droplet-id>
```

**Evidence/Output:**

```
{'dropletId': 12345, 'attachedFirewalls': []}
```

---

### 13. Ensure Operating System on Droplet is Upgraded (Manual)
- **Check ID:** `do_svc_2.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean/droplet/os-upgrade`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Droplet OS version is nearing end-of-life.

**Recommendation (CIS):** Plan and execute an upgrade to a supported OS release.

**Command Executed:**

```
lsb_release -a | cat /etc/os-release
```

**Evidence/Output:**

```
{'distro': 'Ubuntu', 'version': '20.04'}
```

---

### 14. Ensure Operating System is Updated (Manual)
- **Check ID:** `do_svc_2.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean/droplet/os-updates`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Pending OS security updates detected.

**Recommendation (CIS):** Apply latest security updates (e.g., apt update && apt upgrade).

**Command Executed:**

```
apt update && apt list --upgradable
```

**Evidence/Output:**

```
{'pendingUpdates': 12}
```

---

### 15. Ensure auditd is Enabled (Automated)
- **Check ID:** `do_svc_2.6`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean/droplet/auditd`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** auditd is not enabled or running.

**Recommendation (CIS):** Install, enable, and configure auditd with appropriate rules and rotation.

**Command Executed:**

```
systemctl is-enabled auditd && systemctl is-active auditd
```

**Evidence/Output:**

```
{'enabled': False, 'active': False}
```

---

### 16. Ensure SSH Keys are Used to Authenticate (Automated)
- **Check ID:** `do_svc_2.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean/droplet/ssh-key-auth`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Password authentication is enabled for SSH.

**Recommendation (CIS):** Require SSH key authentication and disable password authentication in sshd_config.

**Command Executed:**

```
grep '^PasswordAuthentication' /etc/ssh/sshd_config
```

**Evidence/Output:**

```
{'PasswordAuthentication': 'yes'}
```

---

### 17. Ensure Unused SSH Keys are Deleted (Automated)
- **Check ID:** `do_svc_2.8`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean/droplet/ssh-keys-unused`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Stale SSH keys detected in account or on Droplet.

**Recommendation (CIS):** Remove unused SSH keys from account and authorized_keys on Droplets.

**Command Executed:**

```
doctl compute ssh-key list; grep -n 'ssh-' /home/*/.ssh/authorized_keys
```

**Evidence/Output:**

```
{'staleKeys': ['old-ci-key']}
```

---

### 18. Ensure Log Forwarding is Enabled (Manual)
- **Check ID:** `do_svc_3.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:k8s:log-forwarding`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** DOKS cluster does not have log forwarding destination configured.

**Recommendation (CIS):** Configure Event log forwarding to a Managed OpenSearch destination.

**Command Executed:**

```
(UI) Kubernetes → Cluster → Settings → Event log forwarding
```

**Evidence/Output:**

```
{'destinations': []}
```

---

### 19. Ensure an Upgrade Window is Defined (Automated)
- **Check ID:** `do_svc_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:k8s:upgrade-window`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Automatic minor patch upgrade window is not defined.

**Recommendation (CIS):** Enable automatic minor version patches with a defined 4-hour window.

**Command Executed:**

```
doctl kubernetes cluster get <id|name> --output json
```

**Evidence/Output:**

```
{'autoUpgrade': False, 'maintenanceWindow': None}
```

---

### 20. Ensure High Availability Control Plane is Enabled (Automated)
- **Check ID:** `do_svc_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:k8s:ha-control-plane`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** High availability control plane is not enabled.

**Recommendation (CIS):** Enable HA control plane for increased resiliency and SLA.

**Command Executed:**

```
doctl kubernetes cluster update <id|name> --ha
```

**Evidence/Output:**

```
{'ha': False}
```

---

### 21. Ensure Security History is Monitored (Manual)
- **Check ID:** `do_svc_4.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:account:security-history`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Security history review process is not documented/monitored.

**Recommendation (CIS):** Review Security History regularly via Control Panel → Settings → Security.

**Command Executed:**

```
(UI) Settings → Security → Security History
```

**Evidence/Output:**

```
{'lastReviewed': None}
```

---

### 22. Ensure Resource Monitoring is Enabled (Automated)
- **Check ID:** `do_svc_4.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean/droplet/monitoring`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Droplet does not have the DigitalOcean metrics agent installed.

**Recommendation (CIS):** Enable Monitoring during creation or install the metrics agent manually.

**Command Executed:**

```
doctl compute droplet get <id|name> --output json (monitoring) / install-agent script
```

**Evidence/Output:**

```
{'monitoringEnabled': False}
```

---

### 23. Ensure Access Control to Spaces are Set (Manual)
- **Check ID:** `do_svc_5.1`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:access-control`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Spaces access controls require review for least privilege.

**Recommendation (CIS):** Use Limited access keys and Teams appropriately; review bucket permissions.

**Command Executed:**

```
(UI) Spaces → Access Keys; review bucket permissions
```

**Evidence/Output:**

```
{'accessKeys': [{'name': 'full-access-key', 'scope': 'full'}]}
```

---

### 24. Ensure Access and Secret Keys are Created (Manual)
- **Check ID:** `do_svc_5.2`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:keys`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Spaces access keys not provisioned for required automation.

**Recommendation (CIS):** Create appropriately scoped access/secret keys and store securely.

**Command Executed:**

```
(UI) Spaces → Access Keys → Create Access Key
```

**Evidence/Output:**

```
{'keysPresent': False}
```

---

### 25. Ensure Spaces Bucket Lifecycle Policy is Set (Automated)
- **Check ID:** `do_svc_5.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:lifecycle`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** No lifecycle policy configured for Spaces bucket.

**Recommendation (CIS):** Configure lifecycle to expire objects and remove incomplete multipart uploads.

**Command Executed:**

```
s3cmd getlifecycle s3://<space>; s3cmd expire --expiry-days=30 s3://<space>
```

**Evidence/Output:**

```
{'lifecycleConfigured': False}
```

---

### 26. Ensure File Listing Permissions are Set (Manual)
- **Check ID:** `do_svc_5.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:spaces:file-listing`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Bucket file listing is Public.

**Recommendation (CIS):** Set file listing to Private in bucket settings.

**Command Executed:**

```
(UI) Spaces → Bucket → Settings → File Listing
```

**Evidence/Output:**

```
{'fileListing': 'Public'}
```

---

### 27. Ensure Spaces CDN is Enabled (Manual)
- **Check ID:** `do_svc_5.5`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:cdn`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Spaces CDN is not enabled for performance and resilience.

**Recommendation (CIS):** Enable CDN and configure appropriate Edge Cache TTL.

**Command Executed:**

```
(UI) Spaces → Bucket → Settings → CDN → Enable
```

**Evidence/Output:**

```
{'cdnEnabled': False}
```

---

### 28. Ensure CORS is Enabled (Manual)
- **Check ID:** `do_svc_5.6`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:cors`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** CORS not configured for required cross-origin access.

**Recommendation (CIS):** Configure CORS rules via UI or s3cmd setcors with appropriate origins/methods.

**Command Executed:**

```
s3cmd setcors /path/to/config.xml s3://BUCKET_NAME
```

**Evidence/Output:**

```
{'corsConfigured': False}
```

---

### 29. Ensure Unneeded Spaces Bucket are Destroyed (Manual)
- **Check ID:** `do_svc_5.7`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:spaces:bucket-destruction`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Stale Spaces bucket found that is no longer needed.

**Recommendation (CIS):** Schedule bucket for destruction or cancel if needed.

**Command Executed:**

```
(UI) Spaces → Bucket → Settings → Destroy this Space
```

**Evidence/Output:**

```
{'bucketStatus': 'active', 'lastAccessedDays': 240}
```

---

### 30. Ensure Drive is Encrypted with LUKS on Top of Volume (Manual)
- **Check ID:** `do_svc_6.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:volume:luks`
- **Region:** global
- **Compliance:** CIS DigitalOcean Services Benchmark v1.0.0

**Description:** Attached block volume is not encrypted with LUKS at the filesystem layer.

**Recommendation (CIS):** Configure LUKS on the block device and mount via crypttab/fstab.

**Command Executed:**

```
cryptsetup status secure-volume; lsblk -f
```

**Evidence/Output:**

```
{'luks': False}
```

---