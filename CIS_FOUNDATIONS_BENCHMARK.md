# CIS AWS Foundations Benchmark v6.0.0 Implementation

This document details the implementation of CIS AWS Foundations Benchmark v6.0.0 security checks in CloudAuditor.

## Overview

The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services with an emphasis on foundational, testable, and architecture-agnostic settings.

CloudAuditor implements critical security checks across five major categories:
- **Section 2**: Identity and Access Management (IAM)
- **Section 3**: Storage
- **Section 4**: Logging
- **Section 5**: Monitoring
- **Section 6**: Networking

## Implementation Summary

| Category | Checks Implemented | Severity Levels |
|----------|-------------------|-----------------|
| IAM (Section 2) | 8 checks | CRITICAL, HIGH, MEDIUM |
| Storage (Section 3) | 5 checks | CRITICAL, HIGH, MEDIUM |
| Logging (Section 4) | 5 checks | HIGH, MEDIUM |
| Monitoring (Section 5) | 1 check | MEDIUM |
| Networking (Section 6) | 5 checks | CRITICAL, HIGH, MEDIUM |
| **Total** | **24 checks** | |

## Section 2: Identity and Access Management

### 2.3: Ensure no 'root' user account access key exists
- **Level**: 1
- **Type**: Automated
- **Severity**: CRITICAL
- **Description**: The root user account should not have active access keys. Access keys for the root account should be deleted.
- **Rationale**: The root user has unrestricted access to all AWS services. Compromised root credentials can lead to complete account takeover.

### 2.4: Ensure root user account has MFA enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: CRITICAL
- **Description**: Multi-Factor Authentication (MFA) should be enabled for the root user account.
- **Rationale**: MFA provides an additional layer of protection beyond passwords, significantly reducing the risk of account compromise.

### 2.7: Ensure IAM password policy requires minimum length of 14 or greater
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: Password policies should enforce a minimum password length of at least 14 characters.
- **Rationale**: Longer passwords are exponentially harder to crack and provide better protection against brute force attacks.

### 2.8: Ensure IAM password policy prevents password reuse
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: Password policy should prevent reuse of previous passwords (remember at least 24 passwords).
- **Rationale**: Preventing password reuse ensures that compromised old passwords cannot be reused.

### 2.9: Ensure IAM users with console access have MFA enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: All IAM users with console access should have MFA enabled.
- **Rationale**: MFA protects user accounts from being compromised even if passwords are leaked.

### 2.10: Ensure IAM user credentials unused for 45 days or greater are disabled
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: IAM user credentials that haven't been used in 45+ days should be disabled.
- **Rationale**: Inactive credentials represent unnecessary attack surface and should be removed.

### 2.11: Ensure IAM policies that allow full administrative privileges are not attached
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: IAM policies should not grant full administrative privileges (e.g., Action: *).
- **Rationale**: Following principle of least privilege, users should only have permissions they need.

### 2.18: Ensure IAM access keys are rotated every 90 days or less
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: IAM access keys should be rotated regularly (every 90 days or less).
- **Rationale**: Regular key rotation limits the window of opportunity if keys are compromised.

## Section 3: Storage

### 3.1.1: Ensure S3 buckets require requests to use SSL/HTTPS
- **Level**: 2
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: S3 bucket policies should require all requests to use SSL/HTTPS.
- **Rationale**: Using HTTPS ensures data in transit is encrypted, protecting against man-in-the-middle attacks.

### 3.1.4: Ensure S3 Block Public Access is enabled at the account level
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: S3 Block Public Access should be enabled for all buckets at the account level.
- **Rationale**: Prevents accidental public exposure of sensitive data stored in S3.

### 3.2.1: Ensure RDS instances are not publicly accessible
- **Level**: 1
- **Type**: Automated
- **Severity**: CRITICAL
- **Description**: RDS instances should not be publicly accessible from the internet.
- **Rationale**: Exposing databases to the internet increases attack surface and risk of unauthorized access.

### 3.2.3: Ensure RDS encryption is enabled for all instances
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: All RDS instances should have encryption at rest enabled.
- **Rationale**: Encryption protects data at rest from unauthorized access if storage media is compromised.

### 3.3.1: Ensure EFS encryption is enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: All EFS file systems should be encrypted at rest.
- **Rationale**: Encryption protects file system data from unauthorized access.

## Section 4: Logging

### 4.1: Ensure CloudTrail is enabled in all regions
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: A multi-region CloudTrail trail should be enabled and actively logging.
- **Rationale**: CloudTrail provides visibility into API activity for security analysis, resource change tracking, and compliance auditing.

### 4.2: Ensure CloudTrail log file validation is enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: CloudTrail log file validation should be enabled to ensure log integrity.
- **Rationale**: Log file validation helps detect whether logs have been tampered with after delivery.

### 4.5: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: CloudTrail logs should be encrypted at rest using AWS KMS Customer Master Keys (CMKs).
- **Rationale**: Encrypting logs protects sensitive API activity information from unauthorized access.

### 4.6: Ensure rotation for customer-created symmetric CMKs is enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: Customer-managed KMS keys should have automatic key rotation enabled.
- **Rationale**: Key rotation limits the amount of data encrypted with a single key version, reducing impact if a key is compromised.

### 4.7: Ensure VPC flow logging is enabled in all VPCs
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: VPC Flow Logs should be enabled for all VPCs.
- **Rationale**: VPC Flow Logs capture network traffic information for security analysis and troubleshooting.

## Section 5: Monitoring

### 5.16: Ensure AWS Security Hub is enabled
- **Level**: 1
- **Type**: Automated
- **Severity**: MEDIUM
- **Description**: AWS Security Hub should be enabled in all regions where resources are deployed.
- **Rationale**: Security Hub provides centralized security findings and continuous compliance checks.

**Note**: CIS Foundations Benchmark includes additional monitoring checks (5.1-5.15) for CloudWatch metric filters and alarms. These require specific metric filter patterns and are simplified in the current implementation.

## Section 6: Networking

### 6.3: Ensure security groups do not allow unrestricted ingress to remote server administration ports
- **Level**: 1
- **Type**: Automated
- **Severity**: CRITICAL
- **Description**: Security groups should not allow SSH (port 22) or RDP (port 3389) access from 0.0.0.0/0 or ::/0.
- **Rationale**: Allowing unrestricted access to administrative ports exposes instances to brute force attacks.

**Checks implemented**:
- 6.3.1: SSH (port 22) from 0.0.0.0/0
- 6.3.2: RDP (port 3389) from 0.0.0.0/0

### 6.4: Ensure the default security group restricts all traffic
- **Level**: 2
- **Type**: Automated
- **Severity**: HIGH
- **Description**: Default security groups should have no inbound or outbound rules.
- **Rationale**: Default security groups should not be used; instances should use purpose-built security groups.

### 6.5: Ensure routing tables for VPC peering are least access
- **Level**: 2
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Routing tables for VPC peering connections should follow the principle of least access.
- **Rationale**: Overly permissive routing can expose resources unintentionally across VPC boundaries.

### 6.7: Ensure EC2 instances use IMDSv2
- **Level**: 1
- **Type**: Automated
- **Severity**: HIGH
- **Description**: EC2 instances should be configured to use Instance Metadata Service Version 2 (IMDSv2).
- **Rationale**: IMDSv2 adds session-based authentication to protect against SSRF attacks targeting instance metadata.

## Running CIS Foundations Checks

### Scan with Both Benchmarks (Default)

```bash
# Run both CIS Foundations and Compute benchmarks
cloudauditor scan aws

# With specific region
cloudauditor scan aws --region us-west-2

# With real AWS credentials (requires boto3 and configured AWS credentials)
cloudauditor scan aws --real --profile production
```

### Mock Mode Testing

```bash
# Test without AWS credentials using mock data
cloudauditor scan aws --output json

# Export to markdown
cloudauditor scan aws --output markdown --output-file security-report.md
```

## Understanding Results

### Severity Levels

- **CRITICAL**: Immediate action required. These findings represent severe security risks that could lead to account compromise or data breach.
- **HIGH**: Should be addressed urgently. These findings represent significant security weaknesses.
- **MEDIUM**: Should be addressed in a timely manner. These findings represent security gaps that should be closed.
- **LOW**: Should be reviewed and addressed as time permits.
- **INFO**: Informational findings about security posture (passed checks).

### Finding Status

- **PASSED**: Check passed, no security issue detected
- **FAILED**: Check failed, security issue detected
- **WARNING**: Unable to complete check (usually due to permissions)

### Sample Output

```json
{
  "check_id": "2.3",
  "title": "Root User Has Active Access Keys",
  "severity": "CRITICAL",
  "status": "FAILED",
  "resource_id": "iam:root",
  "description": "The root user account has active access keys.",
  "recommendation": "Delete all root user access keys immediately",
  "compliance_standard": "CIS AWS Foundations Benchmark v6.0.0",
  "region": "us-east-1"
}
```

## Integration with Other Benchmarks

CloudAuditor runs both CIS AWS Foundations Benchmark and CIS AWS Compute Services Benchmark checks simultaneously, providing comprehensive security coverage across your AWS environment.

The scan results include a `compliance_standards` field listing all benchmarks applied:

```json
{
  "compliance_standards": [
    "CIS AWS Foundations Benchmark v6.0.0",
    "CIS AWS Compute Services Benchmark v1.1.0"
  ]
}
```

## Required AWS Permissions

To run all CIS Foundations checks with real AWS credentials, the following permissions are required:

### IAM Permissions
- `iam:GetAccountSummary`
- `iam:GetCredentialReport`
- `iam:GetAccountPasswordPolicy`
- `iam:ListUsers`
- `iam:ListPolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListAccessKeys`

### Storage Permissions
- `s3:ListBuckets`
- `s3:GetBucketPolicy`
- `s3:GetBucketPublicAccessBlock`
- `rds:DescribeDBInstances`
- `elasticfilesystem:DescribeFileSystems`

### Logging Permissions
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `ec2:DescribeVpcs`
- `ec2:DescribeFlowLogs`
- `kms:ListKeys`
- `kms:DescribeKey`
- `kms:GetKeyRotationStatus`

### Monitoring Permissions
- `securityhub:DescribeHub`

### Networking Permissions
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeInstances`

### Recommended IAM Policy

For read-only security scanning, use the AWS managed policy:
- `SecurityAudit` (provides comprehensive read-only access for security auditing)

Or create a custom policy with the specific permissions listed above.

## References

- [CIS AWS Foundations Benchmark v6.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

## Contributing

To add more CIS Foundations checks:

1. Locate the appropriate checker module in `cloudauditor/providers/aws_foundations/`
2. Add your check method following the existing patterns
3. Update the `run_checks()` method to include your new check
4. Add mock data in `_get_mock_findings()` for testing
5. Update this documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

This implementation is provided under the MIT License. See [LICENSE](LICENSE) for details.
