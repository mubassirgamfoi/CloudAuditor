# CloudAuditor Compliance Report

**Generated:** 2025-10-29T17:09:50.570689

**Provider:** AWS

**Region:** us-east-1

**Profile:** default

## Summary

- **Total Checks:** 29
- **Passed:** 0
- **Failed:** 29
- **Warnings:** 0

## Findings

### 1. Root User Has Active Access Keys

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `iam:root`

**Description:** The root user account has active access keys.

**Recommendation:** Delete all root user access keys immediately

---

### 2. Root User MFA Not Enabled

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `iam:root`

**Description:** Multi-factor authentication is not enabled on the root account.

**Recommendation:** Enable MFA on root account immediately

---

### 3. IAM Password Policy: Minimum Length Too Short

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `iam:password-policy`

**Description:** Password minimum length is 8 (CIS requires >= 14 characters).

**Recommendation:** Update password policy to require minimum 14 characters

---

### 4. IAM User Console Access Without MFA

**Severity:** HIGH

**Status:** FAILED

**Resource:** `iam:user/john.doe`

**Description:** IAM user 'john.doe' has console access but no MFA device configured.

**Recommendation:** Enable MFA for all IAM users with console access

---

### 5. IAM Policy Grants Full Administrative Privileges

**Severity:** HIGH

**Status:** FAILED

**Resource:** `arn:aws:iam::123456789012:policy/AdminPolicy`

**Description:** IAM policy 'AdminPolicy' grants full *:* administrative privileges.

**Recommendation:** Replace with specific permissions following principle of least privilege

---

### 6. S3 Bucket Does Not Enforce HTTPS

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `s3://company-data-bucket`

**Description:** S3 bucket does not have a policy to deny HTTP requests.

**Recommendation:** Add bucket policy to deny requests where aws:SecureTransport is false

---

### 7. S3 Block Public Access Not Fully Enabled

**Severity:** HIGH

**Status:** FAILED

**Resource:** `s3://public-assets`

**Description:** S3 bucket does not have all Block Public Access settings enabled.

**Recommendation:** Enable all Block Public Access settings

---

### 8. RDS Instance Publicly Accessible

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `rds:production-db`

**Description:** RDS instance is publicly accessible from the internet.

**Recommendation:** Modify RDS instance to disable public accessibility

---

### 9. CloudTrail Not Enabled in All Regions

**Severity:** HIGH

**Status:** FAILED

**Resource:** `cloudtrail`

**Description:** No multi-region CloudTrail trail is enabled.

**Recommendation:** Create and enable a multi-region CloudTrail trail

---

### 10. CloudTrail Logs Not Encrypted with KMS

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `arn:aws:cloudtrail:us-east-1:123456789012:trail/default`

**Description:** CloudTrail trail does not use KMS encryption.

**Recommendation:** Enable KMS encryption for CloudTrail logs

---

### 11. VPC Flow Logging Not Enabled

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `vpc-0123456789abcdef0`

**Description:** VPC does not have flow logging enabled.

**Recommendation:** Enable VPC flow logs

---

### 12. AWS Security Hub Not Enabled

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `securityhub:us-east-1`

**Description:** AWS Security Hub is not enabled in this region.

**Recommendation:** Enable AWS Security Hub for centralized security findings

---

### 13. Security Group Allows SSH from Internet

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `sg-0123456789abcdef0`

**Description:** Security group allows SSH (port 22) from 0.0.0.0/0.

**Recommendation:** Restrict SSH access to specific IP ranges

---

### 14. Default Security Group Allows Traffic

**Severity:** HIGH

**Status:** FAILED

**Resource:** `sg-default`

**Description:** Default security group has rules allowing traffic.

**Recommendation:** Remove all rules from default security group

---

### 15. EC2 Instance Not Enforcing IMDSv2

**Severity:** HIGH

**Status:** FAILED

**Resource:** `i-0123456789abcdef0`

**Description:** EC2 instance does not enforce IMDSv2.

**Recommendation:** Modify instance metadata options to require IMDSv2

---

### 16. AMI EBS Snapshots Not Encrypted

**Severity:** HIGH

**Status:** FAILED

**Resource:** `ami-0123456789abcdef0`

**Description:** AMI 'web-app-v1.0' has unencrypted EBS snapshots. Data at rest is not encrypted.

**Recommendation:** Copy AMI with encryption enabled using 'aws ec2 copy-image --encrypted'

---

### 17. AMI Older Than 90 Days

**Severity:** MEDIUM

**Status:** FAILED

**Resource:** `ami-0123456789abcdef1`

**Description:** AMI 'api-backend-v2.0' is 145 days old. Outdated AMIs may lack security patches.

**Recommendation:** Create new AMI from updated instance and deregister old AMI

---

### 18. EBS Encryption By Default Not Enabled

**Severity:** HIGH

**Status:** FAILED

**Resource:** `ec2:ebs:encryption:us-east-1`

**Description:** EBS encryption by default is not enabled for this region.

**Recommendation:** Enable EBS encryption by default

---

### 19. EBS Snapshot Not Encrypted

**Severity:** HIGH

**Status:** FAILED

**Resource:** `snap-0123456789abcdef0`

**Description:** EBS snapshot 'prod-db-backup' is not encrypted.

**Recommendation:** Create new encrypted snapshot and delete unencrypted snapshot

---

### 20. Unused EBS Volume Detected

**Severity:** LOW

**Status:** FAILED

**Resource:** `vol-0123456789abcdef0`

**Description:** EBS volume is not attached to any instance.

**Recommendation:** Review volume and delete if no longer needed

---

### 21. EC2 Instance Using Default Security Group

**Severity:** HIGH

**Status:** FAILED

**Resource:** `i-0123456789abcdef0`

**Description:** EC2 instance is using the default security group.

**Recommendation:** Create custom security group with least privilege

---

### 22. IMDSv2 Not Enforced on EC2 Instance

**Severity:** HIGH

**Status:** FAILED

**Resource:** `i-0123456789abcdef1`

**Description:** EC2 instance does not enforce IMDSv2.

**Recommendation:** Enforce IMDSv2 to protect against SSRF attacks

---

### 23. Potential Secrets in EC2 User Data

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `i-0123456789abcdef2`

**Description:** EC2 User Data may contain sensitive information.

**Recommendation:** Use AWS Secrets Manager instead

---

### 24. ECS Task with Host Network Has Privileged Access

**Severity:** HIGH

**Status:** FAILED

**Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:1`

**Description:** ECS task using host network mode allows privileged access.

**Recommendation:** Remove privileged access or run as non-root user

---

### 25. ECS Container Running in Privileged Mode

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/api:2:nginx`

**Description:** ECS container is running in privileged mode.

**Recommendation:** Remove privileged flag

---

### 26. ECS Container Has Secrets in Environment Variables

**Severity:** HIGH

**Status:** FAILED

**Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/worker:3:app`

**Description:** ECS container has potential secret in environment variable 'API_KEY'.

**Recommendation:** Use AWS Secrets Manager instead

---

### 27. Lambda Function Has Overly Permissive IAM Role

**Severity:** HIGH

**Status:** FAILED

**Resource:** `arn:aws:lambda:us-east-1:123456789012:function:data-processor`

**Description:** Lambda function has AdministratorAccess policy attached.

**Recommendation:** Replace with custom policy granting only required permissions

---

### 28. Lambda Function Publicly Accessible

**Severity:** CRITICAL

**Status:** FAILED

**Resource:** `arn:aws:lambda:us-east-1:123456789012:function:api-handler`

**Description:** Lambda function has public access policy.

**Recommendation:** Remove public access and grant permissions to specific principals

---

### 29. Lambda Function Using Deprecated Runtime

**Severity:** HIGH

**Status:** FAILED

**Resource:** `arn:aws:lambda:us-east-1:123456789012:function:legacy-app`

**Description:** Lambda function uses deprecated runtime 'python3.6'.

**Recommendation:** Update to a currently supported runtime version

---