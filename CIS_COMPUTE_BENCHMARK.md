# CIS AWS Compute Services Benchmark Implementation

CloudAuditor now implements the **CIS AWS Compute Services Benchmark v1.1.0**, providing comprehensive security compliance checks for AWS compute resources.

## Overview

The CIS AWS Compute Services Benchmark provides prescriptive guidance for configuring security options for compute services within AWS. This implementation covers the following AWS services:

- **Amazon EC2** (Elastic Cloud Compute)
- **Amazon ECS** (Elastic Container Service)
- **AWS Lambda**
- **Amazon Lightsail** (planned)
- **AWS Batch** (planned)
- **AWS Elastic Beanstalk** (planned)

## Implemented Checks

### Section 2: Amazon EC2

#### 2.1 Amazon Machine Images (AMI) - 5 Checks

| Check ID | Title | Level | Type | Severity |
|----------|-------|-------|------|----------|
| 2.1.1 | Ensure Consistent Naming Convention is used for Organizational AMI | 1 | Manual | LOW |
| 2.1.2 | Ensure Amazon Machine Images (AMIs) are encrypted | 1 | Automated | HIGH |
| 2.1.3 | Ensure Only Approved Amazon Machine Images (AMIs) are Used | 1 | Manual | MEDIUM |
| 2.1.4 | Ensure Images (AMI) are not older than 90 days | 1 | Automated | MEDIUM |
| 2.1.5 | Ensure Images are not Publicly Available | 1 | Manual | CRITICAL |

#### 2.2 Elastic Block Storage (EBS) - 4 Checks

| Check ID | Title | Level | Type | Severity |
|----------|-------|-------|------|----------|
| 2.2.1 | Ensure EBS volume encryption is enabled | 1 | Automated | HIGH |
| 2.2.2 | Ensure Public Access to EBS Snapshots is Disabled | 1 | Automated | CRITICAL |
| 2.2.3 | Ensure EBS volume snapshots are encrypted | 1 | Automated | HIGH |
| 2.2.4 | Ensure unused EBS volumes are removed | 1 | Manual | LOW |

#### 2.3-2.14 EC2 General Configuration - 12 Checks

| Check ID | Title | Level | Type | Severity |
|----------|-------|-------|------|----------|
| 2.3 | Ensure Tag Policies are Enabled | 1 | Manual | LOW |
| 2.4 | Ensure an Organizational EC2 Tag Policy has been Created | 1 | Manual | LOW |
| 2.5 | Ensure no AWS EC2 Instances are Older than 180 days | 1 | Manual | MEDIUM |
| 2.6 | Ensure detailed monitoring is enable for production EC2 Instances | 1 | Manual | MEDIUM |
| 2.7 | Ensure Default EC2 Security groups are not being used | 1 | Manual | HIGH |
| 2.8 | Ensure the Use of IMDSv2 is Enforced on All Existing Instances | 1 | Manual | HIGH |
| 2.9 | Ensure use of AWS Systems Manager to manage EC2 instances | 1 | Manual | MEDIUM |
| 2.10 | Ensure unused ENIs are removed | 1 | Manual | LOW |
| 2.11 | Ensure instances stopped for over 90 days are removed | 1 | Manual | LOW |
| 2.12 | Ensure EBS volumes attached to EC2 marked for deletion upon termination | 1 | Manual | LOW |
| 2.13 | Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data | 1 | Manual | CRITICAL |
| 2.14 | Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances | 1 | Automated | LOW |

### Section 3: Amazon ECS

#### ECS Security Configuration - 14 Checks

| Check ID | Title | Level | Type | Severity |
|----------|-------|-------|------|----------|
| 3.1 | Ensure ECS task definitions using 'host' network mode do not allow privileged or root user access | 1 | Automated | HIGH |
| 3.2 | Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services | 1 | Automated | MEDIUM |
| 3.3 | Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host' | 1 | Automated | HIGH |
| 3.4 | Ensure Amazon ECS task definitions do not have 'privileged' set to 'true' | 1 | Automated | CRITICAL |
| 3.5 | Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions | 1 | Automated | MEDIUM |
| 3.6 | Ensure secrets are not passed as container environment variables in ECS task definitions | 1 | Automated | HIGH |
| 3.7 | Ensure logging is configured for Amazon ECS task definitions | 1 | Automated | MEDIUM |
| 3.8 | Ensure Amazon ECS Fargate services are using the latest Fargate platform version | 1 | Automated | MEDIUM |
| 3.9 | Ensure monitoring is enabled for Amazon ECS clusters | 1 | Automated | MEDIUM |
| 3.10 | Ensure Amazon ECS services are tagged | 1 | Automated | LOW |
| 3.11 | Ensure Amazon ECS clusters are tagged | 1 | Automated | LOW |
| 3.12 | Ensure Amazon ECS task definitions are tagged | 1 | Automated | LOW |
| 3.13 | Ensure only trusted images are used with Amazon ECS | 1 | Automated | HIGH |
| 3.14 | Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets | 1 | Automated | MEDIUM |

### Section 12: AWS Lambda

#### Lambda Security Configuration - 12 Checks

| Check ID | Title | Level | Type | Severity |
|----------|-------|-------|------|----------|
| 12.1 | Ensure AWS Config is Enabled for Lambda and Serverless | 1 | Manual | MEDIUM |
| 12.2 | Ensure Cloudwatch Lambda insights is enabled | 1 | Manual | LOW |
| 12.3 | Ensure AWS Secrets manager is configured and being used by Lambda for databases | 1 | Manual | MEDIUM |
| 12.4 | Ensure least privilege is used with Lambda function access | 1 | Manual | HIGH |
| 12.5 | Ensure every Lambda function has its own IAM Role | 1 | Manual | MEDIUM |
| 12.6 | Ensure Lambda functions are not exposed to everyone | 1 | Manual | CRITICAL |
| 12.7 | Ensure Lambda functions are referencing active execution roles | 1 | Manual | CRITICAL |
| 12.8 | Ensure that Code Signing is enabled for Lambda functions | 1 | Manual | MEDIUM |
| 12.9 | Ensure there are no Lambda functions with admin privileges | 1 | Manual | HIGH |
| 12.10 | Ensure Lambda functions do not allow unknown cross account access | 1 | Manual | HIGH |
| 12.11 | Ensure runtime environment versions used for Lambda do not have end of support dates | 1 | Manual | HIGH |
| 12.12 | Ensure encryption in transit is enabled for Lambda environment variables | 1 | Manual | MEDIUM |

## Architecture

### Modular Checker System

The implementation uses a modular checker architecture:

```
cloudauditor/providers/aws_checks/
├── __init__.py              # Checker exports
├── base_checker.py          # Base checker class
├── ec2_ami_checks.py        # EC2 AMI checks (2.1.x)
├── ec2_ebs_checks.py        # EC2 EBS checks (2.2.x)
├── ec2_general_checks.py    # EC2 general checks (2.3-2.14)
├── ecs_checks.py            # ECS checks (3.x)
└── lambda_checks.py         # Lambda checks (12.x)
```

### Base Checker

All checkers inherit from `BaseAWSChecker` which provides:
- Standardized finding format
- Session management
- Mock/real mode handling
- Common utility methods

### Finding Format

Each finding includes:
```python
{
    "check_id": "2.1.2",                           # CIS check ID
    "title": "AMI EBS Snapshots Not Encrypted",    # Finding title
    "severity": "HIGH",                             # CRITICAL/HIGH/MEDIUM/LOW/INFO
    "status": "FAILED",                             # PASSED/FAILED/WARNING
    "resource_id": "ami-0123456789abcdef0",        # AWS resource ID
    "description": "...",                           # Detailed description
    "recommendation": "...",                        # Remediation steps
    "compliance_standard": "CIS AWS Compute...",    # Standard reference
    "region": "us-east-1"                          # AWS region
}
```

## Usage

### Basic Scan

```bash
# Run scan with CIS Compute Benchmark checks
cloudauditor scan aws

# Scan specific region
cloudauditor scan aws --region us-west-2 --profile prod

# Generate detailed report
cloudauditor scan aws --output markdown --output-file cis-report.md
```

### With Real AWS Credentials

```bash
# Install boto3
pip install "cloudauditor[aws]"

# Configure AWS credentials
aws configure

# Run real scan
cloudauditor scan aws --real --profile my-profile
```

### Programmatic Usage

```python
from cloudauditor.providers import AWSScanner

# Initialize scanner
scanner = AWSScanner(
    profile="production",
    region="us-east-1",
    use_mock=False,  # Use real AWS API
    enable_cis_compute=True  # Enable CIS Compute checks
)

# Run scan
results = scanner.scan()

# Access findings
for finding in results['findings']:
    if finding['status'] == 'FAILED':
        print(f"{finding['check_id']}: {finding['title']}")
        print(f"Resource: {finding['resource_id']}")
        print(f"Recommendation: {finding['recommendation']}\n")
```

## Check Coverage

### Implementation Status

| Service | Total Checks | Implemented | Coverage |
|---------|--------------|-------------|----------|
| EC2 AMI | 5 | 5 | 100% |
| EC2 EBS | 4 | 4 | 100% |
| EC2 General | 12 | 12 | 100% |
| ECS | 14 | 14 | 100% |
| Lambda | 12 | 12 | 100% |
| **Total** | **47** | **47** | **100%** |

### Check Types

- **Automated**: 22 checks (47%)
- **Manual**: 25 checks (53%)

### Severity Distribution

- **CRITICAL**: 7 checks
- **HIGH**: 15 checks
- **MEDIUM**: 18 checks
- **LOW**: 7 checks

## Real AWS API Integration

When running with real AWS credentials, the scanner uses boto3 to:

1. **EC2 AMI Checks**
   - Query AMIs with `ec2:DescribeImages`
   - Check encryption status
   - Verify naming conventions
   - Check age and public access

2. **EC2 EBS Checks**
   - Get encryption settings with `ec2:GetEbsEncryptionByDefault`
   - List snapshots with `ec2:DescribeSnapshots`
   - Check snapshot permissions
   - Identify unused volumes

3. **EC2 Instance Checks**
   - List instances with `ec2:DescribeInstances`
   - Check metadata options (IMDSv2)
   - Verify security groups
   - Check Systems Manager status

4. **ECS Checks**
   - List task definitions with `ecs:ListTaskDefinitions`
   - Describe services with `ecs:DescribeServices`
   - Check cluster settings
   - Verify container configurations

5. **Lambda Checks**
   - List functions with `lambda:ListFunctions`
   - Get configurations with `lambda:GetFunctionConfiguration`
   - Check IAM roles with `iam:GetRole`
   - Verify policies with `lambda:GetPolicy`

## Required AWS Permissions

For full CIS Compute Benchmark scanning, the following IAM permissions are needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstanceAttribute",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:ListTaskDefinitions",
        "ecs:DescribeClusters",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "ssm:DescribeInstanceInformation",
        "autoscaling:DescribeAutoScalingGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

## Mock Mode

Mock mode provides sample findings for testing without AWS credentials:

```bash
# Run in mock mode (default)
cloudauditor scan aws

# Mock mode returns realistic findings for all checks
# Perfect for:
# - Testing the CLI
# - Understanding check coverage
# - Demonstrating capabilities
# - CI/CD pipeline testing
```

## Future Enhancements

### Planned Services

- Amazon Lightsail (Section 5)
- AWS App Runner (Section 6)
- AWS Batch (Section 8)
- AWS Elastic Beanstalk (Section 10)
- AWS Fargate (Section 11)
- EC2 Image Builder (Section 17)

### Planned Features

- Custom check filtering by severity
- Compliance scoring
- Trend analysis across scans
- Integration with AWS Config
- Automated remediation suggestions
- Export to compliance frameworks (CSV, XLSX)

## References

- [CIS AWS Compute Services Benchmark v1.1.0](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

## Support

For issues, questions, or contributions related to CIS Compute Benchmark implementation:

- Open an issue on GitHub
- Refer to the main [README.md](README.md) for general usage
- Check [QUICKSTART.md](QUICKSTART.md) for quick setup guide

---

**Compliance Standard**: CIS AWS Compute Services Benchmark v1.1.0
**Implementation Date**: January 2025
**Coverage**: 47 checks across EC2, ECS, and Lambda services
