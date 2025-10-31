# CIS AWS End User Compute Services Benchmark v1.2.0

This document describes the implementation of the CIS AWS End User Compute Services Benchmark v1.2.0 in CloudAuditor CLI.

## Overview

The CIS AWS End User Compute Services Benchmark v1.2.0 provides prescriptive guidance for configuring security options for AWS End User Computing services. This benchmark covers:

- **Amazon WorkSpaces** - Virtual desktop infrastructure
- **Amazon WorkSpaces Web** - Web-based access to WorkSpaces
- **Amazon WorkDocs** - Document collaboration service
- **Amazon AppStream 2.0** - Application streaming service

## Implementation

### Directory Structure

```
cloudauditor/providers/aws_enduser/
├── __init__.py
├── base_checker.py
├── workspaces_checks.py
├── workspaces_web_checks.py
├── workdocs_checks.py
└── appstream_checks.py
```

### Base Checker

The `EndUserComputeChecker` base class provides common functionality for all End User Compute services:

- Service client initialization
- Common check structure
- Error handling
- Result formatting

### Service-Specific Checkers

#### WorkSpaces Checker (`workspaces_checks.py`)

Implements WorkSpaces security checks:

**Check 2.1: Ensure Administration of WorkSpaces is defined using IAM**
- **Profile**: Level 1
- **Assessment Status**: Manual
- **Description**: Verifies that IAM policies are properly configured for WorkSpaces administration
- **Rationale**: Proper IAM configuration ensures secure administration of WorkSpaces

**Check 2.2: Ensure MFA is enabled for WorkSpaces users**
- **Profile**: Level 2
- **Assessment Status**: Manual
- **Description**: Checks if Multi-Factor Authentication is enabled for WorkSpaces directories
- **Rationale**: MFA provides additional security layer beyond username/password

**Check 2.3: Ensure WorkSpace volumes are encrypted**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Verifies that both root and user volumes are encrypted
- **Rationale**: Encryption protects data at rest

#### WorkSpaces Web Checker (`workspaces_web_checks.py`)

Implements WorkSpaces Web security checks:

**Check 3.1: Ensure WorkSpaces Web portal is configured with proper authentication**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Verifies proper identity provider configuration
- **Rationale**: Proper authentication ensures only authorized users can access portals

**Check 3.2: Ensure WorkSpaces Web portal has network restrictions configured**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Checks for VPC configuration and IP access restrictions
- **Rationale**: Network restrictions prevent unauthorized access

#### WorkDocs Checker (`workdocs_checks.py`)

Implements WorkDocs security checks:

**Check 4.1: Ensure WorkDocs sites have proper access controls**
- **Profile**: Level 1
- **Assessment Status**: Manual
- **Description**: Verifies proper user access controls and permissions
- **Rationale**: Access controls ensure data protection through least privilege

**Check 4.2: Ensure WorkDocs data is encrypted at rest**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Checks for encryption configuration (requires S3 bucket verification)
- **Rationale**: Encryption protects data from unauthorized access

#### AppStream 2.0 Checker (`appstream_checks.py`)

Implements AppStream 2.0 security checks:

**Check 5.1: Ensure AppStream 2.0 stacks have proper security groups configured**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Verifies security group configuration and checks for overly permissive rules
- **Rationale**: Proper security groups control network access

**Check 5.2: Ensure AppStream 2.0 fleets have encryption enabled**
- **Profile**: Level 1
- **Assessment Status**: Automated
- **Description**: Checks for encryption configuration on AppStream fleets
- **Rationale**: Encryption protects sensitive data processed by applications

**Check 5.3: Ensure AppStream 2.0 user access is properly configured**
- **Profile**: Level 1
- **Assessment Status**: Manual
- **Description**: Verifies proper user access controls and authentication
- **Rationale**: Proper access controls ensure only authorized users can access applications

## Usage

### Command Line

```bash
# Run all benchmarks including End User Compute
cloudauditor scan aws --region us-east-1

# Run only End User Compute benchmark
cloudauditor scan aws --region us-east-1 --enable-cis-enduser

# Disable End User Compute benchmark
cloudauditor scan aws --region us-east-1 --disable-cis-enduser
```

### Python API

```python
from cloudauditor.providers.aws import AWSScanner

# Initialize scanner with End User Compute enabled
scanner = AWSScanner(
    region="us-east-1",
    enable_cis_enduser=True
)

# Run scan
results = scanner.scan()
```

## Configuration

The End User Compute benchmark can be enabled/disabled using the `enable_cis_enduser` parameter:

```python
scanner = AWSScanner(
    profile="my-profile",
    region="us-west-2",
    enable_cis_enduser=True,  # Enable End User Compute checks
    enable_cis_foundations=True,
    enable_cis_compute=True,
    enable_cis_databases=True
)
```

## Check Results

Each check returns a standardized result dictionary:

```python
{
    'check_id': 'workspaces_2.1',
    'check_title': 'Ensure Administration of WorkSpaces is defined using IAM',
    'status': 'PASS',  # PASS, FAIL, WARN, ERROR, INFO
    'message': 'Found 3 IAM entities with WorkSpaces administration permissions',
    'details': {
        'workspaces_policies': [...],
        'attached_entities': [...]
    },
    'recommendation': 'Ensure IAM principals have appropriate WorkSpaces administration policies attached'
}
```

## Dependencies

The End User Compute benchmark requires the following AWS services:

- **WorkSpaces**: `workspaces` client
- **WorkSpaces Web**: `workspaces-web` client
- **WorkDocs**: `workdocs` client
- **AppStream 2.0**: `appstream` client
- **IAM**: `iam` client (for policy checks)
- **Directory Service**: `ds` client (for MFA checks)
- **KMS**: `kms` client (for encryption checks)
- **EC2**: `ec2` client (for security group checks)

## Required Permissions

The following IAM permissions are required to run End User Compute checks:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "workspaces:*",
                "workspaces-web:*",
                "workdocs:*",
                "appstream:*",
                "iam:GetPolicy",
                "iam:ListPolicies",
                "iam:GetPolicyVersion",
                "iam:ListEntitiesForPolicy",
                "ds:DescribeDirectories",
                "kms:DescribeKey",
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": "*"
        }
    ]
}
```

## Limitations

1. **Manual Checks**: Some checks require manual verification as they cannot be fully automated
2. **Service Availability**: Checks depend on the availability of AWS services in the target region
3. **Permissions**: Some checks may fail if insufficient permissions are granted
4. **Mock Mode**: In mock mode, checks return informational results rather than actual AWS data

## Error Handling

The implementation includes comprehensive error handling:

- **Service Unavailable**: Graceful handling when services are not available
- **Permission Denied**: Clear error messages for insufficient permissions
- **API Errors**: Proper error logging and user-friendly messages
- **Network Issues**: Timeout and retry logic for network-related errors

## Compliance Standards

This implementation follows:

- **CIS AWS End User Compute Services Benchmark v1.2.0**
- **CIS Controls v8** (where applicable)
- **AWS Security Best Practices**

## Future Enhancements

Planned improvements include:

1. **Enhanced Mock Data**: More realistic mock data for testing
2. **Additional Checks**: More comprehensive security checks
3. **Performance Optimization**: Improved check execution speed
4. **Better Error Messages**: More detailed error reporting
5. **Integration Tests**: Comprehensive test coverage

## Support

For issues or questions regarding the End User Compute benchmark implementation:

1. Check the logs for detailed error messages
2. Verify AWS permissions and service availability
3. Review the CIS benchmark documentation
4. Submit issues through the project repository
