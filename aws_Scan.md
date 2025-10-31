# CloudAuditor Compliance Report

**Generated:** 2025-10-29T19:46:08.555039
**Provider:** AWS
**Region:** us-east-1
**Profile/Project:** default
**Command:** `cloudauditor scan aws --output markdown --output-file aws_Scan.md --real`

## Benchmarks Executed
- CIS AWS Foundations Benchmark v6.0.0
- CIS AWS Compute Services Benchmark v1.1.0
- CIS AWS Database Services Benchmark v1.0.0
- CIS AWS End User Compute Services Benchmark v1.2.0
- CIS AWS Storage Services Benchmark v1.0.0

## Summary
- **Total Checks:** 59
- **Passed:** 3
- **Failed:** 27
- **Warnings:** 24

## Findings

### 1. Root User Has Active Access Keys
- **Check ID:** `2.3`
- **Severity:** CRITICAL
- **Status:** FAILED
- **Resource:** `iam:root`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** The root user account has active access keys. This is a critical security risk.

**Recommendation (CIS):** Delete all root user access keys immediately via AWS Console

**Command Executed:**

```
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text
```

**Evidence/Output:**

```
{'GroupPolicySizeQuota': 5120, 'InstanceProfilesQuota': 1000, 'Policies': 3, 'GroupsPerUserQuota': 10, 'InstanceProfiles': 1, 'AttachedPoliciesPerUserQuota': 10, 'Users': 3, 'PoliciesQuota': 1500, 'Providers': 0, 'AccountMFAEnabled': 0, 'AccessKeysPerUserQuota': 2, 'AssumeRolePolicySizeQuota': 2048, 'PolicyVersionsInUseQuota': 10000, 'GlobalEndpointTokenVersion': 1, 'VersionsPerPolicyQuota': 5, 'AttachedPoliciesPerGroupQuota': 10, 'PolicySizeQuota': 6144, 'Groups': 0, 'AccountSigningCertificatesPresent': 0, 'UsersQuota': 5000, 'ServerCertificatesQuota': 20, 'MFADevices': 0, 'UserPolicySizeQuota': 2048, 'PolicyVersionsInUse': 9, 'ServerCertificates': 0, 'Roles': 8, 'RolesQuota': 1000, 'SigningCertificatesPerUserQuota': 2, 'MFADevicesInUse': 0, 'RolePolicySizeQuota': 10240, 'AttachedPoliciesPerRoleQuota': 10, 'AccountAccessKeysPresent': 1, 'AccountPasswordPresent': 1, 'GroupsQuota': 300}
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

**Recommendation (CIS):** Enable MFA on root account immediately using virtual or hardware MFA device

**Command Executed:**

```
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text
```

**Evidence/Output:**

```
{'GroupPolicySizeQuota': 5120, 'InstanceProfilesQuota': 1000, 'Policies': 3, 'GroupsPerUserQuota': 10, 'InstanceProfiles': 1, 'AttachedPoliciesPerUserQuota': 10, 'Users': 3, 'PoliciesQuota': 1500, 'Providers': 0, 'AccountMFAEnabled': 0, 'AccessKeysPerUserQuota': 2, 'AssumeRolePolicySizeQuota': 2048, 'PolicyVersionsInUseQuota': 10000, 'GlobalEndpointTokenVersion': 1, 'VersionsPerPolicyQuota': 5, 'AttachedPoliciesPerGroupQuota': 10, 'PolicySizeQuota': 6144, 'Groups': 0, 'AccountSigningCertificatesPresent': 0, 'UsersQuota': 5000, 'ServerCertificatesQuota': 20, 'MFADevices': 0, 'UserPolicySizeQuota': 2048, 'PolicyVersionsInUse': 9, 'ServerCertificates': 0, 'Roles': 8, 'RolesQuota': 1000, 'SigningCertificatesPerUserQuota': 2, 'MFADevicesInUse': 0, 'RolePolicySizeQuota': 10240, 'AttachedPoliciesPerRoleQuota': 10, 'AccountAccessKeysPresent': 1, 'AccountPasswordPresent': 1, 'GroupsQuota': 300}
```

---

### 3. IAM Password Policy Not Configured
- **Check ID:** `2.7`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `iam:password-policy`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** No IAM password policy is configured for the account.

**Recommendation (CIS):** Create IAM password policy with CIS recommended settings

---

### 4. IAM Access Key Unused for 45+ Days
- **Check ID:** `2.11`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_admin_user/key/AKIAW3MECWTN7LRAVZ6G`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Access key 'AKIAW3MECWTN7LRAVZ6G' for user 'cgidbll40hzhwk_admin_user' unused for 63 days.

**Recommendation (CIS):** Disable or delete unused access keys

**Command Executed:**

```
aws iam get-access-key-last-used --access-key-id AKIAW3MECWTN7LRAVZ6G
```

**Evidence/Output:**

```
{'AccessKeyId': 'AKIAW3MECWTN7LRAVZ6G', 'LastUsedDate': '2025-08-27T18:12:00+00:00', 'DaysUnused': 63}
```

---

### 5. IAM Access Key Unused for 45+ Days
- **Check ID:** `2.11`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_low_priv_user/key/AKIAW3MECWTNY3FSIF63`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Access key 'AKIAW3MECWTNY3FSIF63' for user 'cgidbll40hzhwk_low_priv_user' unused for 63 days.

**Recommendation (CIS):** Disable or delete unused access keys

**Command Executed:**

```
aws iam get-access-key-last-used --access-key-id AKIAW3MECWTNY3FSIF63
```

**Evidence/Output:**

```
{'AccessKeyId': 'AKIAW3MECWTNY3FSIF63', 'LastUsedDate': '2025-08-27T16:55:00+00:00', 'DaysUnused': 63}
```

---

### 6. IAM Access Key Unused for 45+ Days
- **Check ID:** `2.11`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_secondary_user/key/AKIAW3MECWTNWR4Z4DNZ`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Access key 'AKIAW3MECWTNWR4Z4DNZ' for user 'cgidbll40hzhwk_secondary_user' unused for 63 days.

**Recommendation (CIS):** Disable or delete unused access keys

**Command Executed:**

```
aws iam get-access-key-last-used --access-key-id AKIAW3MECWTNWR4Z4DNZ
```

**Evidence/Output:**

```
{'AccessKeyId': 'AKIAW3MECWTNWR4Z4DNZ', 'LastUsedDate': '2025-08-27T18:23:00+00:00', 'DaysUnused': 63}
```

---

### 7. IAM User Has Direct Policy Attachments
- **Check ID:** `2.14`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_admin_user`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM user 'cgidbll40hzhwk_admin_user' has policies attached directly instead of through groups.

**Recommendation (CIS):** Remove direct policy attachments and grant permissions only through IAM groups

---

### 8. IAM User Has Direct Policy Attachments
- **Check ID:** `2.14`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_low_priv_user`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM user 'cgidbll40hzhwk_low_priv_user' has policies attached directly instead of through groups.

**Recommendation (CIS):** Remove direct policy attachments and grant permissions only through IAM groups

---

### 9. IAM User Has Direct Policy Attachments
- **Check ID:** `2.14`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `iam:user/cgidbll40hzhwk_secondary_user`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM user 'cgidbll40hzhwk_secondary_user' has policies attached directly instead of through groups.

**Recommendation (CIS):** Remove direct policy attachments and grant permissions only through IAM groups

---

### 10. IAM Policy Grants Full Administrative Privileges
- **Check ID:** `2.15`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `arn:aws:iam::471112791259:policy/cgidbll40hzhwk_admin_user_policy`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM policy 'cgidbll40hzhwk_admin_user_policy' grants full *:* administrative privileges.

**Recommendation (CIS):** Replace with specific permissions following principle of least privilege

---

### 11. No AWS Support Role Configured
- **Check ID:** `2.16`
- **Severity:** LOW
- **Status:** FAILED
- **Resource:** `iam:support-role`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** No IAM role with AWSSupportAccess policy is configured for managing AWS Support cases.

**Recommendation (CIS):** Create IAM role with AWSSupportAccess policy for incident management

---

### 12. IAM Access Analyzer Not Enabled
- **Check ID:** `2.19`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `accessanalyzer:us-east-1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** IAM Access Analyzer is not enabled in region us-east-1.

**Recommendation (CIS):** Enable IAM Access Analyzer in all regions to identify resources shared with external entities

---

### 13. S3 Bucket Does Not Enforce HTTPS
- **Check ID:** `3.1.1`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `s3://aws-cloudtrail-logs-471112791259-ff410b6b`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** S3 bucket 'aws-cloudtrail-logs-471112791259-ff410b6b' does not have a policy to deny HTTP requests.

**Recommendation (CIS):** Add bucket policy to deny requests where aws:SecureTransport is false

**Command Executed:**

```
aws s3api get-bucket-policy --bucket aws-cloudtrail-logs-471112791259-ff410b6b --query Policy --output text
```

**Evidence/Output:**

```
{'Version': '2012-10-17', 'Statement': [{'Sid': 'AWSCloudTrailAclCheck20150319-99151375-50d6-4dc3-9e59-cf008b388e24', 'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:GetBucketAcl', 'Resource': 'arn:aws:s3:::aws-cloudtrail-logs-471112791259-ff410b6b', 'Condition': {'StringEquals': {'AWS:SourceArn': 'arn:aws:cloudtrail:us-east-2:471112791259:trail/management-events'}}}, {'Sid': 'AWSCloudTrailWrite20150319-09c4966d-fa71-47ec-acbf-55e3fd946a6b', 'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:PutObject', 'Resource': 'arn:aws:s3:::aws-cloudtrail-logs-471112791259-ff410b6b/AWSLogs/471112791259/*', 'Condition': {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control', 'AWS:SourceArn': 'arn:aws:cloudtrail:us-east-2:471112791259:trail/management-events'}}}]}
```

---

### 14. S3 Bucket Does Not Enforce HTTPS
- **Check ID:** `3.1.1`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `s3://elasticbeanstalk-us-east-1-471112791259`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** S3 bucket 'elasticbeanstalk-us-east-1-471112791259' does not have a policy to deny HTTP requests.

**Recommendation (CIS):** Add bucket policy to deny requests where aws:SecureTransport is false

**Command Executed:**

```
aws s3api get-bucket-policy --bucket elasticbeanstalk-us-east-1-471112791259 --query Policy --output text
```

**Evidence/Output:**

```
{'Version': '2008-10-17', 'Statement': [{'Sid': 'eb-af163bf3-d27b-4712-b795-d1e33e331ca4', 'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::471112791259:role/cgidbll40hzhwk_eb_instance_role'}, 'Action': ['s3:ListBucket', 's3:ListBucketVersions', 's3:GetObject', 's3:GetObjectVersion'], 'Resource': ['arn:aws:s3:::elasticbeanstalk-us-east-1-471112791259', 'arn:aws:s3:::elasticbeanstalk-us-east-1-471112791259/resources/environments/*']}, {'Sid': 'eb-58950a8c-feb6-11e2-89e0-0800277d041b', 'Effect': 'Deny', 'Principal': {'AWS': '*'}, 'Action': 's3:DeleteBucket', 'Resource': 'arn:aws:s3:::elasticbeanstalk-us-east-1-471112791259'}]}
```

---

### 15. Unable to Check S3 HTTPS Enforcement
- **Check ID:** `3.1.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `s3`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Could not verify S3 bucket policies: <botocore.errorfactory.S3Exceptions object at 0x000001AE638E6F90> object has no attribute NoSuchBucketPolicy. Valid exceptions are: BucketAlreadyExists, BucketAlreadyOwnedByYou, EncryptionTypeMismatch, IdempotencyParameterMismatch, InvalidObjectState, InvalidRequest, InvalidWriteOffset, NoSuchBucket, NoSuchKey, NoSuchUpload, ObjectAlreadyInActiveTierError, ObjectNotInActiveTierError, TooManyParts

**Recommendation (CIS):** Verify S3 permissions

---

### 16. S3 Block Public Access Not Fully Enabled
- **Check ID:** `3.1.4`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `s3://elasticbeanstalk-us-east-1-471112791259`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** S3 bucket 'elasticbeanstalk-us-east-1-471112791259' does not have all Block Public Access settings enabled.

**Recommendation (CIS):** Enable all Block Public Access settings on the bucket

---

### 17. CloudTrail Not Enabled in All Regions
- **Check ID:** `4.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `cloudtrail`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** No multi-region CloudTrail trail is enabled and logging.

**Recommendation (CIS):** Create and enable a multi-region CloudTrail trail

**Command Executed:**

```
aws cloudtrail describe-trails --region us-east-1 --query 'trailList[?IsMultiRegionTrail==`true` && IsLogging==`true`]'
```

**Evidence/Output:**

```
{'trailList': [{'Name': 'management-events', 'S3BucketName': 'aws-cloudtrail-logs-471112791259-ff410b6b', 'IncludeGlobalServiceEvents': True, 'IsMultiRegionTrail': True, 'HomeRegion': 'us-east-2', 'TrailARN': 'arn:aws:cloudtrail:us-east-2:471112791259:trail/management-events', 'LogFileValidationEnabled': False, 'HasCustomEventSelectors': True, 'HasInsightSelectors': False, 'IsOrganizationTrail': False}], 'ResponseMetadata': {'RequestId': '7db9f71c-2146-47d0-be1a-556e1913a3d3', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '7db9f71c-2146-47d0-be1a-556e1913a3d3', 'content-type': 'application/x-amz-json-1.1', 'content-length': '387', 'date': 'Wed, 29 Oct 2025 23:45:43 GMT'}, 'RetryAttempts': 0}}
```

---

### 18. Unable to Check CloudTrail Log Validation
- **Check ID:** `4.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `cloudtrail`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Could not verify log validation: An error occurred (TrailNotFoundException) when calling the GetTrailStatus operation: Unknown trail: arn:aws:cloudtrail:us-east-1:471112791259:trail/management-events for the user: 471112791259

**Recommendation (CIS):** Verify CloudTrail permissions

---

### 19. CloudTrail Logs Not Encrypted with KMS
- **Check ID:** `4.5`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `arn:aws:cloudtrail:us-east-2:471112791259:trail/management-events`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** CloudTrail trail 'management-events' does not use KMS encryption.

**Recommendation (CIS):** Enable KMS encryption for CloudTrail logs

**Command Executed:**

```
aws cloudtrail describe-trails --trail-name-list management-events --query 'trailList[0].KmsKeyId'
```

**Evidence/Output:**

```
{'KmsKeyId': None, 'TrailName': 'management-events'}
```

---

### 20. VPC Flow Logging Not Enabled
- **Check ID:** `4.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `vpc-0ec2f6ed743828899`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** VPC 'vpc-0ec2f6ed743828899' does not have flow logging enabled.

**Recommendation (CIS):** Enable VPC flow logs for network traffic monitoring

**Command Executed:**

```
aws ec2 describe-flow-logs --filters Name=resource-id,Values=vpc-0ec2f6ed743828899
```

**Evidence/Output:**

```
{'FlowLogs': [], 'ResponseMetadata': {'RequestId': 'c240b822-235d-4e53-9218-cba89fe50488', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'c240b822-235d-4e53-9218-cba89fe50488', 'cache-control': 'no-cache, no-store', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'vary': 'accept-encoding', 'content-type': 'text/xml;charset=UTF-8', 'transfer-encoding': 'chunked', 'date': 'Wed, 29 Oct 2025 23:45:45 GMT', 'server': 'AmazonEC2'}, 'RetryAttempts': 0}}
```

---

### 21. VPC Flow Logging Not Enabled
- **Check ID:** `4.7`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `vpc-0158ac103a1bb5642`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** VPC 'vpc-0158ac103a1bb5642' does not have flow logging enabled.

**Recommendation (CIS):** Enable VPC flow logs for network traffic monitoring

**Command Executed:**

```
aws ec2 describe-flow-logs --filters Name=resource-id,Values=vpc-0158ac103a1bb5642
```

**Evidence/Output:**

```
{'FlowLogs': [], 'ResponseMetadata': {'RequestId': '31aca0fb-7c3c-4436-8f88-600375aef486', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '31aca0fb-7c3c-4436-8f88-600375aef486', 'cache-control': 'no-cache, no-store', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'vary': 'accept-encoding', 'content-type': 'text/xml;charset=UTF-8', 'transfer-encoding': 'chunked', 'date': 'Wed, 29 Oct 2025 23:45:45 GMT', 'server': 'AmazonEC2'}, 'RetryAttempts': 0}}
```

---

### 22. AWS Security Hub Not Enabled
- **Check ID:** `5.16`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `securityhub:us-east-1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** AWS Security Hub is not enabled in this region.

**Recommendation (CIS):** Enable AWS Security Hub for centralized security findings

---

### 23. Default Security Group Allows Traffic
- **Check ID:** `6.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `sg-0fc6f65f2c92828b1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Default security group 'sg-0fc6f65f2c92828b1' has rules allowing traffic.

**Recommendation (CIS):** Remove all inbound and outbound rules from default security group

---

### 24. Default Security Group Allows Traffic
- **Check ID:** `6.5`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `sg-07778c019a2cbf2f1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Foundations Benchmark v6.0.0

**Description:** Default security group 'sg-07778c019a2cbf2f1' has rules allowing traffic.

**Recommendation (CIS):** Remove all inbound and outbound rules from default security group

---

### 25. EBS Encryption By Default Not Enabled
- **Check ID:** `2.2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `ec2:ebs:encryption:us-east-1`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EBS encryption by default is not enabled for this region. New volumes will not be automatically encrypted.

**Recommendation (CIS):** Enable EBS encryption by default using 'aws ec2 enable-ebs-encryption-by-default'

---

### 26. Unable to Check Instance Age
- **Check ID:** `2.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `ec2:instances`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** Could not verify instance age: type object 'datetime.datetime' has no attribute 'timezone'

**Recommendation (CIS):** Verify AWS permissions for ec2:DescribeInstances

---

### 27. EC2 Instance Not Managed by Systems Manager
- **Check ID:** `2.9`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `i-0554f34dc08ccd8ea`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** EC2 instance is not managed by AWS Systems Manager. This limits management capabilities.

**Recommendation (CIS):** Install SSM Agent and attach IAM role with AmazonSSMManagedInstanceCore policy

---

### 28. Unable to Check Stopped Instances
- **Check ID:** `2.11`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `ec2:instances`
- **Region:** us-east-1
- **Compliance:** CIS AWS Compute Services Benchmark v1.1.0

**Description:** Could not verify stopped instances: type object 'datetime.datetime' has no attribute 'timezone'

**Recommendation (CIS):** Verify AWS permissions for ec2:DescribeInstances

---

### 29. Ensure Administration of WorkSpaces is defined using IAM
- **Check ID:** `workspaces_2.1`
- **Severity:** MEDIUM
- **Status:** FAILED
- **Resource:** `aws:workspaces:administration`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces administration IAM policies not properly configured

**Recommendation (CIS):** Configure proper IAM policies for WorkSpaces administration

---

### 30. Ensure WorkSpace volumes are encrypted
- **Check ID:** `workspaces_2.3`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:workspaces:volumes`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces volumes are properly encrypted

**Recommendation (CIS):** Continue monitoring encryption settings

---

### 31. Ensure WorkSpaces Web portal is configured with proper authentication
- **Check ID:** `workspaces_web_3.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:workspaces-web:authentication`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkSpaces Web authentication configuration needs review

**Recommendation (CIS):** Configure proper identity providers for WorkSpaces Web portals

---

### 32. Ensure WorkDocs sites have proper access controls
- **Check ID:** `workdocs_4.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:workdocs:access-controls`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** WorkDocs access controls require manual verification

**Recommendation (CIS):** Review and configure proper user access controls for WorkDocs sites

---

### 33. Ensure AppStream 2.0 stacks have proper security groups configured
- **Check ID:** `appstream_5.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:appstream:security-groups`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** AppStream security groups need review for overly permissive rules

**Recommendation (CIS):** Review and tighten security group rules

---

### 34. Ensure AppStream 2.0 fleets have encryption enabled
- **Check ID:** `appstream_5.2`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:appstream:encryption`
- **Region:** us-east-1
- **Compliance:** CIS AWS End User Compute Services Benchmark v1.2.0

**Description:** AppStream 2.0 fleets have encryption enabled

**Recommendation (CIS):** Continue monitoring encryption settings

---

### 35. AWS Storage Backups (Manual)
- **Check ID:** `backup_1.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:storage`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Storage Backups configuration needs review

**Recommendation (CIS):** Configure AWS Backup service for high resiliency

---

### 36. Ensure securing AWS Backups (Manual)
- **Check ID:** `backup_1.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:security`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup security configuration needs review

**Recommendation (CIS):** Implement proper security measures for AWS Backups

---

### 37. Ensure to create backup template and name (Manual)
- **Check ID:** `backup_1.3`
- **Severity:** LOW
- **Status:** INFO
- **Resource:** `aws:backup:template`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Backup template configuration is in place

**Recommendation (CIS):** Review backup template naming conventions

---

### 38. Ensure to create AWS IAM Policies (Manual)
- **Check ID:** `backup_1.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:iam-policies`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup IAM policies need review

**Recommendation (CIS):** Create and configure appropriate IAM policies for AWS Backup

---

### 39. Ensure to create IAM roles for Backup (Manual)
- **Check ID:** `backup_1.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:backup:iam-roles`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Backup IAM roles need review

**Recommendation (CIS):** Create and configure appropriate IAM roles for AWS Backup

---

### 40. Ensure AWS Backup with Service Linked Roles (Manual)
- **Check ID:** `backup_1.6`
- **Severity:** LOW
- **Status:** INFO
- **Resource:** `aws:backup:service-linked-roles`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Service Linked Roles for AWS Backup are configured

**Recommendation (CIS):** Review Service Linked Roles configuration

---

### 41. Ensure creating EC2 instance with EBS (Manual)
- **Check ID:** `ebs_2.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:ebs:ec2-instance`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EC2 instance with EBS configuration needs review

**Recommendation (CIS):** Ensure EC2 instances are properly configured with EBS volumes

---

### 42. Ensure configuring Security Groups (Manual)
- **Check ID:** `ebs_2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aws:ebs:security-groups`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Security groups for EBS are not properly configured

**Recommendation (CIS):** Configure security groups to restrict traffic to necessary ports only

---

### 43. Ensure the proper configuration of EBS storage (Manual)
- **Check ID:** `ebs_2.3`
- **Severity:** HIGH
- **Status:** PASSED
- **Resource:** `aws:ebs:storage`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EBS storage is properly configured

**Recommendation (CIS):** Continue monitoring EBS configuration

---

### 44. Ensure the creation of a new volume (Manual)
- **Check ID:** `ebs_2.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:ebs:new-volume`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** New EBS volume creation process needs review

**Recommendation (CIS):** Ensure proper volume creation with encryption and delete protection

---

### 45. Ensure creating snapshots of EBS volumes (Manual)
- **Check ID:** `ebs_2.5`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `aws:ebs:snapshots`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EBS volume snapshots are not being created regularly

**Recommendation (CIS):** Implement regular EBS volume snapshots for data protection

---

### 46. EFS (Manual)
- **Check ID:** `efs_3.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:efs:filesystem`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS file system is configured

**Recommendation (CIS):** Review EFS configuration regularly

---

### 47. Ensure Implementation of EFS (Manual)
- **Check ID:** `efs_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:efs:implementation`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS implementation needs review

**Recommendation (CIS):** Ensure proper EFS implementation with encryption

---

### 48. Ensure EFS and VPC Integration (Manual)
- **Check ID:** `efs_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:efs:vpc-integration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** EFS and VPC integration needs review

**Recommendation (CIS):** Ensure proper EFS and VPC integration for redundancy

---

### 49. FSX (AWS Elastic File Cache) (Manual)
- **Check ID:** `fsx_4.1`
- **Severity:** MEDIUM
- **Status:** INFO
- **Resource:** `aws:fsx:file-cache`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Elastic File Cache is configured

**Recommendation (CIS):** Review FSx file cache configuration

---

### 50. Amazon Elastic File Cache (Manual)
- **Check ID:** `fsx_4.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:fsx:elastic-file-cache`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Elastic File Cache configuration needs review

**Recommendation (CIS):** Ensure proper Elastic File Cache configuration

---

### 51. Ensure the creation of an FSX Bucket (Manual)
- **Check ID:** `fsx_4.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:fsx:s3-bucket`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 bucket for FSx needs creation

**Recommendation (CIS):** Create and configure S3 bucket for FSx data storage

---

### 52. Amazon Simple Storage Service (Manual)
- **Check ID:** `s3_5.1`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:bucket`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 bucket configuration needs review

**Recommendation (CIS):** Configure S3 with proper access controls and encryption

---

### 53. Ensure direct data addition to S3 (Manual)
- **Check ID:** `s3_5.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:data-addition`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Direct data addition to S3 process needs review

**Recommendation (CIS):** Ensure secure direct data addition to S3

---

### 54. Ensure Storage Classes are Configured (Manual)
- **Check ID:** `s3_5.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:s3:storage-classes`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** S3 storage classes need proper configuration

**Recommendation (CIS):** Configure appropriate S3 storage classes for cost optimization

---

### 55. Ensure Elastic Disaster Recovery is Configured (Manual)
- **Check ID:** `edr_6.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `aws:edr:disaster-recovery`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Elastic Disaster Recovery is not properly configured

**Recommendation (CIS):** Configure AWS Elastic Disaster Recovery for high resiliency

---

### 56. Ensure AWS Disaster Recovery Configuration (Manual)
- **Check ID:** `edr_6.2`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `aws:edr:configuration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** AWS Disaster Recovery configuration needs review

**Recommendation (CIS):** Review and update AWS Disaster Recovery configuration

---

### 57. Ensure functionality of Endpoint Detection and Response (EDR) (Manual)
- **Check ID:** `edr_6.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:endpoint-detection`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Endpoint Detection and Response functionality needs review

**Recommendation (CIS):** Ensure EDR functionality is properly configured

---

### 58. Ensure configuration of replication settings (Manual)
- **Check ID:** `edr_6.4`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:replication-settings`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** Replication settings need configuration

**Recommendation (CIS):** Configure proper replication settings for disaster recovery

---

### 59. Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)
- **Check ID:** `edr_6.5`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `aws:edr:iam-configuration`
- **Region:** us-east-1
- **Compliance:** CIS AWS Storage Services Benchmark v1.0.0

**Description:** IAM configuration for EDR needs review

**Recommendation (CIS):** Configure proper IAM policies and roles for EDR

---