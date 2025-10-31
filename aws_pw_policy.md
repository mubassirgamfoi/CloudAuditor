# CloudAuditor Compliance Report

**Generated:** 2025-10-30T01:34:13.760664
**Provider:** AWS
**Region:** us-east-1
**Profile/Project:** test
**Command:** `cloudauditor scan aws --profile test --output markdown --output-file aws_pw_policy.md`

## Benchmarks Executed
- CIS AWS Foundations Benchmark v6.0.0
- CIS AWS Compute Services Benchmark v1.1.0
- CIS AWS Database Services Benchmark v1.0.0
- CIS AWS End User Compute Services Benchmark v1.2.0
- CIS AWS Storage Services Benchmark v1.0.0

## Summary
- **Total Checks:** 88
- **Passed:** 3
- **Failed:** 60
- **Warnings:** 20

## Findings

### 1. Root User Has Active Access Keys
- **Check ID:** `2.3`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `iam:root`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** The root user account has active access keys.

**Recommendation (CIS):** Delete all root user access keys immediately

**Command Executed:**

```
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text
```

**Evidence/Output:**

```
{'AccountAccessKeysPresent': 1}
```

---

### 2. Root User MFA Not Enabled
- **Check ID:** `2.4`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `iam:root`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Multi-factor authentication is not enabled on the root account.

**Recommendation (CIS):** Enable MFA on root account immediately

**Command Executed:**

```
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text
```

**Evidence/Output:**

```
{'AccountMFAEnabled': 0}
```

---

### 3. IAM Password Policy: Minimum Length Too Short
- **Check ID:** `2.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:password-policy`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Password minimum length is 8 (CIS requires >= 14 characters).

**Recommendation (CIS):** Update password policy to require minimum 14 characters

**Command Executed:**

```
aws iam get-account-password-policy
```

**Evidence/Output:**

```
{'MinimumPasswordLength': 8, 'PasswordReusePrevention': 12}
```

---

### 4. IAM User Console Access Without MFA
- **Check ID:** `2.9`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `iam:user/john.doe`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM user 'john.doe' has console access but no MFA device configured.

**Recommendation (CIS):** Enable MFA for all IAM users with console access

**Command Executed:**

```
aws iam list-mfa-devices --user-name john.doe
```

**Evidence/Output:**

```
{'MFADevices': []}
```

---

### 5. IAM Policy Grants Full Administrative Privileges
- **Check ID:** `2.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:iam::123456789012:policy/AdminPolicy`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM policy 'AdminPolicy' grants full *:* administrative privileges.

**Recommendation (CIS):** Replace with specific permissions following principle of least privilege

**Command Executed:**

```
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/AdminPolicy --version-id v1
```

**Evidence/Output:**

```
{'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
```

---

### 6. S3 Bucket Does Not Enforce HTTPS
- **Check ID:** `3.1.1`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `s3://company-data-bucket`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** S3 bucket does not have a policy to deny HTTP requests.

**Recommendation (CIS):** Add bucket policy to deny requests where aws:SecureTransport is false

**Command Executed:**

```
aws s3api get-bucket-policy --bucket company-data-bucket --query Policy --output text
```

**Evidence/Output:**

```
{'Statement': [{'Sid': 'AllowAll', 'Effect': 'Allow', 'Principal': '*', 'Action': 's3:*', 'Resource': '*'}]}
```

---

### 7. S3 Block Public Access Not Fully Enabled
- **Check ID:** `3.1.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `s3://public-assets`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** S3 bucket does not have all Block Public Access settings enabled.

**Recommendation (CIS):** Enable all Block Public Access settings

**Command Executed:**

```
aws s3api get-public-access-block --bucket public-assets
```

**Evidence/Output:**

```
{'PublicAccessBlockConfiguration': {'BlockPublicAcls': False, 'IgnorePublicAcls': True, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False}}
```

---

### 8. RDS Instance Publicly Accessible
- **Check ID:** `3.2.3`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `rds:production-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** RDS instance is publicly accessible from the internet.

**Recommendation (CIS):** Modify RDS instance to disable public accessibility

**Command Executed:**

```
aws rds describe-db-instances --query 'DBInstances[?DBInstanceIdentifier==`production-db`].PubliclyAccessible' --output text
```

**Evidence/Output:**

```
True
```

---

### 9. CloudTrail Not Enabled in All Regions
- **Check ID:** `4.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `cloudtrail`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** No multi-region CloudTrail trail is enabled.

**Recommendation (CIS):** Create and enable a multi-region CloudTrail trail

**Command Executed:**

```
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true` && IsLogging==`true`]'
```

**Evidence/Output:**

```
{'trailList': []}
```

---

### 10. CloudTrail Logs Not Encrypted with KMS
- **Check ID:** `4.5`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `arn:aws:cloudtrail:us-east-1:123456789012:trail/default`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** CloudTrail trail does not use KMS encryption.

**Recommendation (CIS):** Enable KMS encryption for CloudTrail logs

**Command Executed:**

```
aws cloudtrail describe-trails --trail-name-list default --query 'trailList[0].KmsKeyId'
```

**Evidence/Output:**

```
{'KmsKeyId': None, 'TrailName': 'default'}
```

---

### 11. VPC Flow Logging Not Enabled
- **Check ID:** `4.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `vpc-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** VPC does not have flow logging enabled.

**Recommendation (CIS):** Enable VPC flow logs

**Command Executed:**

```
aws ec2 describe-flow-logs --filters Name=resource-id,Values=vpc-0123456789abcdef0
```

**Evidence/Output:**

```
{'FlowLogs': []}
```

---

### 12. AWS Security Hub Not Enabled
- **Check ID:** `5.16`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `securityhub:us-east-1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** AWS Security Hub is not enabled in this region.

**Recommendation (CIS):** Enable AWS Security Hub for centralized security findings

**Command Executed:**

```
aws securityhub describe-hub --region us-east-1
```

**Evidence/Output:**

```
{'Error': 'InvalidAccessException', 'HubArn': None}
```

---

### 13. Security Group Allows SSH from Internet
- **Check ID:** `6.3`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `sg-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Security group allows SSH (port 22) from 0.0.0.0/0.

**Recommendation (CIS):** Restrict SSH access to specific IP ranges

**Command Executed:**

```
aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0 --query 'SecurityGroups[0].IpPermissions[?FromPort<=`22` && ToPort>=`22`]'
```

**Evidence/Output:**

```
{'FromPort': 22, 'ToPort': 22, 'CidrIp': '0.0.0.0/0', 'Port': 22}
```

---

### 14. Default Security Group Allows Traffic
- **Check ID:** `6.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `sg-default`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Default security group has rules allowing traffic.

**Recommendation (CIS):** Remove all rules from default security group

**Command Executed:**

```
aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[0].{IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}'
```

**Evidence/Output:**

```
{'IpPermissions': [{'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}], 'IpPermissionsEgress': []}
```

---

### 15. EC2 Instance Not Enforcing IMDSv2
- **Check ID:** `6.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `i-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** EC2 instance does not enforce IMDSv2.

**Recommendation (CIS):** Modify instance metadata options to require IMDSv2

**Command Executed:**

```
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens'
```

**Evidence/Output:**

```
{'HttpTokens': 'optional', 'HttpEndpoint': 'enabled'}
```

---

### 16. AMI EBS Snapshots Not Encrypted
- **Check ID:** `2.1.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `ami-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** AMI 'web-app-v1.0' has unencrypted EBS snapshots. Data at rest is not encrypted.

**Recommendation (CIS):** Copy AMI with encryption enabled using 'aws ec2 copy-image --encrypted'

**Command Executed:**

```
aws ec2 describe-images --image-ids ami-0123456789abcdef0 --query 'Images[0].BlockDeviceMappings[0].Ebs.Encrypted'
```

**Evidence/Output:**

```
{'Encrypted': False, 'SnapshotId': 'snap-0123456789abcdef0', 'VolumeSize': 8}
```

---

### 17. AMI Older Than 90 Days
- **Check ID:** `2.1.4`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `ami-0123456789abcdef1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** AMI 'api-backend-v2.0' is 145 days old. Outdated AMIs may lack security patches.

**Recommendation (CIS):** Create new AMI from updated instance and deregister old AMI

**Command Executed:**

```
aws ec2 describe-images --image-ids ami-0123456789abcdef1 --query 'Images[0].CreationDate'
```

**Evidence/Output:**

```
{'CreationDate': '2024-06-01T10:30:00.000Z', 'DaysOld': 145, 'Name': 'api-backend-v2.0'}
```

---

### 18. EBS Encryption By Default Not Enabled
- **Check ID:** `2.2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `ec2:ebs:encryption:us-east-1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EBS encryption by default is not enabled for this region.

**Recommendation (CIS):** Enable EBS encryption by default

**Command Executed:**

```
aws ec2 get-ebs-encryption-by-default --region us-east-1
```

**Evidence/Output:**

```
{'EbsEncryptionByDefault': False}
```

---

### 19. EBS Snapshot Not Encrypted
- **Check ID:** `2.2.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `snap-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EBS snapshot 'prod-db-backup' is not encrypted.

**Recommendation (CIS):** Create new encrypted snapshot and delete unencrypted snapshot

**Command Executed:**

```
aws ec2 describe-snapshots --snapshot-ids snap-0123456789abcdef0 --query 'Snapshots[0].Encrypted'
```

**Evidence/Output:**

```
{'Encrypted': False, 'SnapshotId': 'snap-0123456789abcdef0', 'Description': 'prod-db-backup'}
```

---

### 20. Unused EBS Volume Detected
- **Check ID:** `2.2.4`
- **Severity:** LOW
- **Status:** FAILED
- **Resource:** `vol-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EBS volume is not attached to any instance.

**Recommendation (CIS):** Review volume and delete if no longer needed

**Command Executed:**

```
aws ec2 describe-volumes --volume-ids vol-0123456789abcdef0 --query 'Volumes[0].Attachments'
```

**Evidence/Output:**

```
{'Attachments': [], 'State': 'available', 'VolumeId': 'vol-0123456789abcdef0'}
```

---

### 21. EC2 Instance Using Default Security Group
- **Check ID:** `2.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `i-0123456789abcdef0`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EC2 instance is using the default security group.

**Recommendation (CIS):** Create custom security group with least privilege

**Command Executed:**

```
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --query 'Reservations[0].Instances[0].SecurityGroups'
```

**Evidence/Output:**

```
{'SecurityGroups': [{'GroupId': 'sg-default', 'GroupName': 'default'}]}
```

---

### 22. IMDSv2 Not Enforced on EC2 Instance
- **Check ID:** `2.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `i-0123456789abcdef1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EC2 instance does not enforce IMDSv2.

**Recommendation (CIS):** Enforce IMDSv2 to protect against SSRF attacks

**Command Executed:**

```
aws ec2 describe-instances --instance-ids i-0123456789abcdef1 --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens'
```

**Evidence/Output:**

```
{'HttpTokens': 'optional', 'HttpEndpoint': 'enabled'}
```

---

### 23. Potential Secrets in EC2 User Data
- **Check ID:** `2.13`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `i-0123456789abcdef2`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EC2 User Data may contain sensitive information.

**Recommendation (CIS):** Use AWS Secrets Manager instead

**Command Executed:**

```
aws ec2 describe-instance-attribute --instance-id i-0123456789abcdef2 --attribute userData --query 'UserData.Value' --output text | base64 -d
```

**Evidence/Output:**

```
{'UserDataContainsSecrets': True, 'SecretsFound': ['password', 'secret', 'key']}
```

---

### 24. ECS Task with Host Network Has Privileged Access
- **Check ID:** `3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** ECS task using host network mode allows privileged access.

**Recommendation (CIS):** Remove privileged access or run as non-root user

**Command Executed:**

```
aws ecs describe-task-definition --task-definition web-app:1 --query 'taskDefinition.containerDefinitions[0].{NetworkMode:networkMode,Privileged:privileged}'
```

**Evidence/Output:**

```
{'NetworkMode': 'host', 'Privileged': True, 'User': 'root'}
```

---

### 25. ECS Container Running in Privileged Mode
- **Check ID:** `3.4`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/api:2:nginx`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** ECS container is running in privileged mode.

**Recommendation (CIS):** Remove privileged flag

**Command Executed:**

```
aws ecs describe-task-definition --task-definition api:2 --query 'taskDefinition.containerDefinitions[?name==`nginx`].Privileged'
```

**Evidence/Output:**

```
{'Privileged': True, 'ContainerName': 'nginx', 'Image': 'nginx:latest'}
```

---

### 26. ECS Container Has Secrets in Environment Variables
- **Check ID:** `3.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:ecs:us-east-1:123456789012:task-definition/worker:3:app`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** ECS container has potential secret in environment variable 'API_KEY'.

**Recommendation (CIS):** Use AWS Secrets Manager instead

**Command Executed:**

```
aws ecs describe-task-definition --task-definition worker:3 --query 'taskDefinition.containerDefinitions[?name==`app`].environment'
```

**Evidence/Output:**

```
{'Environment': [{'name': 'API_KEY', 'value': 'sk-1234567890abcdef'}], 'SecretsInEnv': True}
```

---

### 27. Lambda Function Has Overly Permissive IAM Role
- **Check ID:** `12.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:lambda:us-east-1:123456789012:function:data-processor`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** Lambda function has AdministratorAccess policy attached.

**Recommendation (CIS):** Replace with custom policy granting only required permissions

**Command Executed:**

```
aws lambda get-function --function-name data-processor --query 'Configuration.Role'
```

**Evidence/Output:**

```
{'Role': 'arn:aws:iam::123456789012:role/AdministratorAccess', 'Policies': ['AdministratorAccess']}
```

---

### 28. Lambda Function Publicly Accessible
- **Check ID:** `12.6`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `arn:aws:lambda:us-east-1:123456789012:function:api-handler`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** Lambda function has public access policy.

**Recommendation (CIS):** Remove public access and grant permissions to specific principals

**Command Executed:**

```
aws lambda get-policy --function-name api-handler
```

**Evidence/Output:**

```
{'Policy': '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}'}
```

---

### 29. Lambda Function Using Deprecated Runtime
- **Check ID:** `12.11`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:lambda:us-east-1:123456789012:function:legacy-app`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** Lambda function uses deprecated runtime 'python3.6'.

**Recommendation (CIS):** Update to a currently supported runtime version

**Command Executed:**

```
aws lambda get-function --function-name legacy-app --query 'Configuration.Runtime'
```

**Evidence/Output:**

```
{'Runtime': 'python3.6', 'Deprecated': True, 'SupportedRuntimes': ['python3.9', 'python3.10', 'python3.11']}
```

---

### 30. Aurora Cluster Not Encrypted at Rest
- **Check ID:** `2.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aurora-cluster-prod-001`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Aurora cluster 'aurora-cluster-prod-001' does not have encryption at rest enabled. Data stored is not encrypted.

**Recommendation (CIS):** Enable encryption at rest for the Aurora cluster using AWS KMS. Note: This requires creating a new encrypted cluster and migrating data.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 31. SSL/TLS Not Enforced for Aurora Connections
- **Check ID:** `2.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aurora-cluster-prod-001`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Aurora cluster does not enforce SSL/TLS for client connections. Data in transit may not be encrypted.

**Recommendation (CIS):** Configure Aurora to require SSL/TLS connections and update client applications to use SSL certificates.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 32. Aurora Audit Logging Not Enabled
- **Check ID:** `2.6`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `aurora-cluster-prod-001`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Database Activity Streams or CloudTrail logging is not enabled for Aurora cluster.

**Recommendation (CIS):** Enable Amazon RDS Database Activity Streams or configure CloudTrail logging for comprehensive audit trails.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 33. Aurora Master Password Not Recently Rotated
- **Check ID:** `2.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `aurora-cluster-prod-001`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** The master password for Aurora cluster has not been rotated in over 90 days.

**Recommendation (CIS):** Rotate the master password regularly (at least every 90 days) following your organization's password policy.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 34. Aurora Backup Retention Period Too Short
- **Check ID:** `2.10`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `aurora-cluster-prod-001`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Aurora cluster has a backup retention period of only 1 day. This may not meet compliance requirements.

**Recommendation (CIS):** Configure backup retention period to at least 7 days, or longer based on compliance requirements.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 35. RDS Instance Not Encrypted at Rest
- **Check ID:** `3.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `rds-mysql-prod-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** RDS instance 'rds-mysql-prod-db' does not have encryption at rest enabled.

**Recommendation (CIS):** Enable encryption at rest for RDS instance using AWS KMS. Requires creating a snapshot, copying with encryption, and restoring.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 36. RDS SSL/TLS Connection Not Enforced
- **Check ID:** `3.6`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `rds-mysql-prod-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** RDS instance does not enforce SSL/TLS connections. Database connections may be unencrypted.

**Recommendation (CIS):** Configure RDS parameter group to require SSL and update application connection strings to use SSL.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 37. RDS Auto Minor Version Upgrade Disabled
- **Check ID:** `3.8`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `rds-mysql-prod-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** RDS instance does not have auto minor version upgrade enabled, potentially missing security patches.

**Recommendation (CIS):** Enable auto minor version upgrade in RDS instance settings to automatically apply security patches.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 38. RDS Enhanced Monitoring Not Enabled
- **Check ID:** `3.9`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `rds-mysql-prod-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Enhanced Monitoring is not enabled for RDS instance, limiting visibility into database performance.

**Recommendation (CIS):** Enable Enhanced Monitoring for RDS instance to collect metrics at 1-60 second intervals.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 39. RDS Automated Backups Retention Too Short
- **Check ID:** `3.10`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `rds-mysql-prod-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** RDS automated backup retention period is set to 1 day, which may not meet compliance requirements.

**Recommendation (CIS):** Configure automated backup retention period to at least 7 days or as required by compliance policies.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 40. RDS Instance Not in VPC
- **Check ID:** `3.3`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `rds-mysql-legacy-db`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** RDS instance is using EC2-Classic platform instead of VPC, lacking modern network security controls.

**Recommendation (CIS):** Migrate RDS instance to VPC for improved network isolation and security group controls.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 41. DynamoDB Table Not Encrypted at Rest
- **Check ID:** `4.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `dynamodb-table-users`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** DynamoDB table 'users' does not have encryption at rest enabled using AWS KMS.

**Recommendation (CIS):** Enable encryption at rest for DynamoDB table using AWS KMS customer managed keys (CMK).

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 42. DynamoDB Client Not Using HTTPS
- **Check ID:** `4.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `dynamodb-table-users`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Application connections to DynamoDB are not enforcing HTTPS/TLS encryption.

**Recommendation (CIS):** Configure application to use HTTPS endpoints and enforce TLS 1.2 or higher for DynamoDB connections.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 43. DynamoDB VPC Endpoint Not Configured
- **Check ID:** `4.5`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `vpc-0a1b2c3d4e5f`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** VPC does not have a VPC endpoint for DynamoDB, forcing traffic over public internet.

**Recommendation (CIS):** Create a VPC endpoint for DynamoDB to keep traffic within AWS network.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 44. DynamoDB CloudTrail Logging Not Enabled
- **Check ID:** `4.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `dynamodb-table-users`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** CloudTrail logging is not enabled for DynamoDB API calls, limiting audit capabilities.

**Recommendation (CIS):** Enable CloudTrail logging for DynamoDB to track all API calls and data plane operations.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 45. ElastiCache Cluster Not Encrypted at Rest
- **Check ID:** `5.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `elasticache-redis-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** ElastiCache Redis cluster does not have encryption at rest enabled.

**Recommendation (CIS):** Enable encryption at rest for ElastiCache cluster. Note: Requires creating a new cluster with encryption enabled.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 46. ElastiCache In-Transit Encryption Not Enabled
- **Check ID:** `5.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `elasticache-redis-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** ElastiCache Redis cluster does not have in-transit encryption (TLS) enabled.

**Recommendation (CIS):** Enable in-transit encryption for ElastiCache Redis cluster to protect data during transmission.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 47. ElastiCache Cluster Not in VPC
- **Check ID:** `5.5`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `elasticache-memcached-legacy`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** ElastiCache cluster is not deployed in a VPC, lacking network isolation.

**Recommendation (CIS):** Migrate ElastiCache cluster to VPC for improved network security and isolation.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 48. ElastiCache AUTH Token Not Configured
- **Check ID:** `5.8`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `elasticache-redis-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Redis AUTH token is not configured for ElastiCache cluster, allowing unauthenticated access.

**Recommendation (CIS):** Configure Redis AUTH token to require password authentication for all connections.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 49. ElastiCache CloudWatch Logs Not Enabled
- **Check ID:** `5.6`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `elasticache-redis-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Slow log delivery to CloudWatch is not enabled for ElastiCache Redis cluster.

**Recommendation (CIS):** Enable slow log delivery to CloudWatch Logs for monitoring and troubleshooting.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 50. DocumentDB Cluster Not Encrypted at Rest
- **Check ID:** `7.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `docdb-cluster-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** DocumentDB cluster does not have encryption at rest enabled using AWS KMS.

**Recommendation (CIS):** Enable encryption at rest for DocumentDB cluster. Note: Requires creating a new encrypted cluster and migrating data.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 51. DocumentDB TLS Not Enforced
- **Check ID:** `7.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `docdb-cluster-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** DocumentDB cluster does not enforce TLS for client connections.

**Recommendation (CIS):** Enable TLS enforcement in DocumentDB cluster parameter group and update client applications to use TLS.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 52. DocumentDB Audit Logging Not Enabled
- **Check ID:** `7.6`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `docdb-cluster-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Audit logging is not enabled for DocumentDB cluster, limiting compliance and forensic capabilities.

**Recommendation (CIS):** Enable audit logging in DocumentDB cluster parameter group and export logs to CloudWatch Logs.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 53. DocumentDB Backup Retention Too Short
- **Check ID:** `7.9`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `docdb-cluster-prod`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** DocumentDB cluster backup retention period is only 1 day, which may not meet compliance requirements.

**Recommendation (CIS):** Configure backup retention period to at least 7 days or as required by organizational policies.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 54. Neptune Cluster Not Encrypted at Rest
- **Check ID:** `9.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `neptune-cluster-graphdb`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Neptune cluster does not have encryption at rest enabled using AWS KMS.

**Recommendation (CIS):** Enable encryption at rest for Neptune cluster. Requires creating a new encrypted cluster and migrating data.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 55. Neptune SSL/TLS Not Enforced
- **Check ID:** `9.3`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `neptune-cluster-graphdb`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Neptune cluster does not enforce SSL/TLS for client connections.

**Recommendation (CIS):** Configure Neptune to require SSL/TLS connections and update client applications to use encrypted connections.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 56. Neptune IAM Database Authentication Not Enabled
- **Check ID:** `9.4`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `neptune-cluster-graphdb`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** IAM database authentication is not enabled for Neptune cluster, relying only on database passwords.

**Recommendation (CIS):** Enable IAM database authentication for Neptune to use IAM roles and temporary credentials.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 57. Neptune Audit Logging Not Enabled
- **Check ID:** `9.5`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `neptune-cluster-graphdb`
- **Region:** us-east-1
- **Compliance:** CIS AWS Database Services Benchmark v1.0.0

**Description:** Audit logs are not being exported to CloudWatch Logs for Neptune cluster.

**Recommendation (CIS):** Enable audit log export to CloudWatch Logs in Neptune cluster configuration.

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 58. Ensure Administration of WorkSpaces is defined using IAM
- **Check ID:** `workspaces_2.1`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `aws:workspaces:administration`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces administration IAM policies not properly configured

**Recommendation (CIS):** Configure proper IAM policies for WorkSpaces administration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 59. Ensure WorkSpace volumes are encrypted
- **Check ID:** `workspaces_2.3`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:workspaces:volumes`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces volumes are properly encrypted

**Recommendation (CIS):** Continue monitoring encryption settings

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 60. Ensure WorkSpaces Web portal is configured with proper authentication
- **Check ID:** `workspaces_web_3.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:workspaces-web:authentication`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces Web authentication configuration needs review

**Recommendation (CIS):** Configure proper identity providers for WorkSpaces Web portals

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 61. Ensure WorkDocs sites have proper access controls
- **Check ID:** `workdocs_4.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:workdocs:access-controls`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkDocs access controls require manual verification

**Recommendation (CIS):** Review and configure proper user access controls for WorkDocs sites

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 62. Ensure AppStream 2.0 stacks have proper security groups configured
- **Check ID:** `appstream_5.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:appstream:security-groups`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** AppStream security groups need review for overly permissive rules

**Recommendation (CIS):** Review and tighten security group rules

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 63. Ensure AppStream 2.0 fleets have encryption enabled
- **Check ID:** `appstream_5.2`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:appstream:encryption`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** AppStream 2.0 fleets have encryption enabled

**Recommendation (CIS):** Continue monitoring encryption settings

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 64. AWS Storage Backups (Manual)
- **Check ID:** `backup_1.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:storage`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Storage Backups configuration needs review

**Recommendation (CIS):** Configure AWS Backup service for high resiliency

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 65. Ensure securing AWS Backups (Manual)
- **Check ID:** `backup_1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:security`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup security configuration needs review

**Recommendation (CIS):** Implement proper security measures for AWS Backups

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 66. Ensure to create backup template and name (Manual)
- **Check ID:** `backup_1.3`
- **Severity:** LOW
- **Status:** INFO
- **Resource:** `aws:backup:template`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Backup template configuration is in place

**Recommendation (CIS):** Review backup template naming conventions

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 67. Ensure to create AWS IAM Policies (Manual)
- **Check ID:** `backup_1.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:iam-policies`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup IAM policies need review

**Recommendation (CIS):** Create and configure appropriate IAM policies for AWS Backup

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 68. Ensure to create IAM roles for Backup (Manual)
- **Check ID:** `backup_1.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:iam-roles`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup IAM roles need review

**Recommendation (CIS):** Create and configure appropriate IAM roles for AWS Backup

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 69. Ensure AWS Backup with Service Linked Roles (Manual)
- **Check ID:** `backup_1.6`
- **Severity:** LOW
- **Status:** INFO
- **Resource:** `aws:backup:service-linked-roles`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Service Linked Roles for AWS Backup are configured

**Recommendation (CIS):** Review Service Linked Roles configuration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 70. Ensure creating EC2 instance with EBS (Manual)
- **Check ID:** `ebs_2.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:ebs:ec2-instance`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EC2 instance with EBS configuration needs review

**Recommendation (CIS):** Ensure EC2 instances are properly configured with EBS volumes

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 71. Ensure configuring Security Groups (Manual)
- **Check ID:** `ebs_2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aws:ebs:security-groups`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Security groups for EBS are not properly configured

**Recommendation (CIS):** Configure security groups to restrict traffic to necessary ports only

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 72. Ensure the proper configuration of EBS storage (Manual)
- **Check ID:** `ebs_2.3`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:ebs:storage`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EBS storage is properly configured

**Recommendation (CIS):** Continue monitoring EBS configuration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 73. Ensure the creation of a new volume (Manual)
- **Check ID:** `ebs_2.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:ebs:new-volume`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** New EBS volume creation process needs review

**Recommendation (CIS):** Ensure proper volume creation with encryption and delete protection

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 74. Ensure creating snapshots of EBS volumes (Manual)
- **Check ID:** `ebs_2.5`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `aws:ebs:snapshots`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EBS volume snapshots are not being created regularly

**Recommendation (CIS):** Implement regular EBS volume snapshots for data protection

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 75. EFS (Manual)
- **Check ID:** `efs_3.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:efs:filesystem`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS file system is configured

**Recommendation (CIS):** Review EFS configuration regularly

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 76. Ensure Implementation of EFS (Manual)
- **Check ID:** `efs_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:efs:implementation`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS implementation needs review

**Recommendation (CIS):** Ensure proper EFS implementation with encryption

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 77. Ensure EFS and VPC Integration (Manual)
- **Check ID:** `efs_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:efs:vpc-integration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS and VPC integration needs review

**Recommendation (CIS):** Ensure proper EFS and VPC integration for redundancy

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 78. FSX (AWS Elastic File Cache) (Manual)
- **Check ID:** `fsx_4.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:fsx:file-cache`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Elastic File Cache is configured

**Recommendation (CIS):** Review FSx file cache configuration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 79. Amazon Elastic File Cache (Manual)
- **Check ID:** `fsx_4.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:fsx:elastic-file-cache`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Elastic File Cache configuration needs review

**Recommendation (CIS):** Ensure proper Elastic File Cache configuration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 80. Ensure the creation of an FSX Bucket (Manual)
- **Check ID:** `fsx_4.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:fsx:s3-bucket`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 bucket for FSx needs creation

**Recommendation (CIS):** Create and configure S3 bucket for FSx data storage

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 81. Amazon Simple Storage Service (Manual)
- **Check ID:** `s3_5.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:bucket`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 bucket configuration needs review

**Recommendation (CIS):** Configure S3 with proper access controls and encryption

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 82. Ensure direct data addition to S3 (Manual)
- **Check ID:** `s3_5.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:data-addition`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Direct data addition to S3 process needs review

**Recommendation (CIS):** Ensure secure direct data addition to S3

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 83. Ensure Storage Classes are Configured (Manual)
- **Check ID:** `s3_5.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:storage-classes`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 storage classes need proper configuration

**Recommendation (CIS):** Configure appropriate S3 storage classes for cost optimization

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 84. Ensure Elastic Disaster Recovery is Configured (Manual)
- **Check ID:** `edr_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aws:edr:disaster-recovery`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Elastic Disaster Recovery is not properly configured

**Recommendation (CIS):** Configure AWS Elastic Disaster Recovery for high resiliency

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 85. Ensure AWS Disaster Recovery Configuration (Manual)
- **Check ID:** `edr_6.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `aws:edr:configuration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Disaster Recovery configuration needs review

**Recommendation (CIS):** Review and update AWS Disaster Recovery configuration

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 86. Ensure functionality of Endpoint Detection and Response (EDR) (Manual)
- **Check ID:** `edr_6.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:endpoint-detection`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Endpoint Detection and Response functionality needs review

**Recommendation (CIS):** Ensure EDR functionality is properly configured

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 87. Ensure configuration of replication settings (Manual)
- **Check ID:** `edr_6.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:replication-settings`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Replication settings need configuration

**Recommendation (CIS):** Configure proper replication settings for disaster recovery

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---

### 88. Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)
- **Check ID:** `edr_6.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:iam-configuration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** IAM configuration for EDR needs review

**Recommendation (CIS):** Configure proper IAM policies and roles for EDR

**Command Executed:**

```
aws <service> <describe|get> ... --output json
```

**Evidence/Output:**

```
No evidence provided
```

---