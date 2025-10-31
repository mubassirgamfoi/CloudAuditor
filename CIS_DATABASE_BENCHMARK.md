# CIS AWS Database Services Benchmark v1.0.0 Implementation

This document details the implementation of CIS AWS Database Services Benchmark v1.0.0 security checks in CloudAuditor.

## Overview

The CIS AWS Database Services Benchmark provides prescriptive guidance for configuring security options for AWS database services. This benchmark focuses on database-specific security configurations that go beyond the foundational AWS security settings.

CloudAuditor implements security checks across 6 major AWS database services:
- **Amazon Aurora** (MySQL and PostgreSQL-compatible)
- **Amazon RDS** (Relational Database Service)
- **Amazon DynamoDB** (NoSQL database)
- **Amazon ElastiCache** (In-memory caching)
- **Amazon DocumentDB** (MongoDB-compatible)
- **Amazon Neptune** (Graph database)

## Implementation Summary

| Service | Checks Implemented | CIS Section | Key Focus Areas |
|---------|-------------------|-------------|-----------------|
| Aurora | 5 checks | Section 2 | Encryption, SSL/TLS, Audit logging, Backups |
| RDS | 6 checks | Section 3 | Encryption, VPC, Patching, Monitoring |
| DynamoDB | 4 checks | Section 4 | Encryption, VPC endpoints, Logging |
| ElastiCache | 5 checks | Section 5 | Encryption, VPC, Authentication |
| DocumentDB | 4 checks | Section 7 | Encryption, TLS, Audit logging, Backups |
| Neptune | 4 checks | Section 9 | Encryption, SSL/TLS, IAM auth, Logging |
| **Total** | **28 checks** | | |

**Note:** The CIS Database Services Benchmark includes 82 total checks across 11 services. CloudAuditor implements the most critical checks for the 6 most commonly used services, focusing on automated and testable controls.

## Section 2: Amazon Aurora

Amazon Aurora is a MySQL and PostgreSQL-compatible relational database built for the cloud.

### 2.3: Ensure Data at Rest is Encrypted
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Aurora clusters should have encryption at rest enabled using AWS KMS.
- **Rationale**: Encryption protects data from unauthorized access if storage media is compromised.
- **Impact**: Requires creating a new encrypted cluster and migrating data.

### 2.4: Ensure Data in Transit is Encrypted
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Aurora should enforce SSL/TLS for all client connections.
- **Rationale**: Protects data during transmission from man-in-the-middle attacks.
- **Recommendation**: Configure cluster to require SSL and update client applications.

### 2.6: Ensure Database Audit Logging is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable Database Activity Streams or CloudTrail logging for Aurora.
- **Rationale**: Provides audit trails for compliance and forensic investigations.
- **Recommendation**: Enable RDS Database Activity Streams for comprehensive logging.

### 2.7: Ensure Passwords are Regularly Rotated
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Master passwords should be rotated regularly (at least every 90 days).
- **Rationale**: Limits exposure window if credentials are compromised.
- **Recommendation**: Implement automated password rotation using AWS Secrets Manager.

### 2.10: Ensure Automatic Backups and Retention Policies are configured
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Configure backup retention period to meet compliance requirements (minimum 7 days).
- **Rationale**: Ensures ability to recover from data loss or corruption.
- **Recommendation**: Set retention period based on RPO/RTO requirements.

## Section 3: Amazon RDS

Amazon RDS supports multiple database engines including MySQL, PostgreSQL, Oracle, SQL Server, and MariaDB.

### 3.3: Ensure to Create a Virtual Private Cloud (VPC)
- **Level**: 1
- **Type**: Manual
- **Severity**: CRITICAL
- **Description**: RDS instances must be deployed in a VPC, not EC2-Classic.
- **Rationale**: VPC provides network isolation and modern security controls.
- **Impact**: EC2-Classic is deprecated and lacks security features.

### 3.5: Enable Encryption at Rest
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: RDS instances should have encryption at rest enabled.
- **Rationale**: Protects sensitive data stored in databases.
- **Recommendation**: Enable encryption during instance creation or migrate to encrypted instance.

### 3.6: Enable Encryption in Transit
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Configure RDS to require SSL/TLS connections.
- **Rationale**: Protects data during transmission between application and database.
- **Recommendation**: Set rds.force_ssl=1 in parameter group.

### 3.8: Ensure to Regularly Patch Systems
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable auto minor version upgrade for RDS instances.
- **Rationale**: Automatically applies security patches and bug fixes.
- **Recommendation**: Enable during instance creation or modify existing instance.

### 3.9: Ensure Monitoring and Logging is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable Enhanced Monitoring for RDS instances.
- **Rationale**: Provides detailed metrics for performance and security monitoring.
- **Recommendation**: Enable Enhanced Monitoring with appropriate granularity (60 seconds recommended).

### 3.10: Ensure to Enable Backup and Recovery
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Configure automated backup retention period (minimum 7 days).
- **Rationale**: Ensures data can be recovered in case of failures.
- **Recommendation**: Set retention period based on business requirements.

## Section 4: Amazon DynamoDB

Amazon DynamoDB is a fully managed NoSQL database service.

### 4.3: Ensure DynamoDB Encryption at Rest
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: DynamoDB tables should use encryption at rest with AWS KMS.
- **Rationale**: Protects sensitive data stored in NoSQL databases.
- **Recommendation**: Enable encryption using customer managed KMS keys (CMK).

### 4.4: Ensure DynamoDB Encryption in Transit
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Applications should use HTTPS endpoints for DynamoDB connections.
- **Rationale**: Protects data during API calls.
- **Recommendation**: Configure SDK to enforce TLS 1.2 or higher.

### 4.5: Ensure VPC Endpoints are configured
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Use VPC endpoints for DynamoDB to keep traffic within AWS network.
- **Rationale**: Reduces exposure to internet-based threats.
- **Recommendation**: Create gateway VPC endpoint for DynamoDB in each VPC.

### 4.7: Ensure Monitor and Audit Activity is enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable CloudTrail logging for DynamoDB API calls.
- **Rationale**: Provides audit trail for compliance and security investigations.
- **Recommendation**: Configure CloudTrail to log all DynamoDB data plane operations.

## Section 5: Amazon ElastiCache

Amazon ElastiCache is a fully managed in-memory caching service supporting Redis and Memcached.

### 5.3: Ensure Encryption at Rest and in Transit is configured
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: ElastiCache Redis clusters should have encryption at rest and in-transit enabled.
- **Rationale**: Protects cached sensitive data.
- **Impact**: Requires creating new cluster; cannot be enabled on existing clusters.

### 5.5: Ensure Virtual Private Cloud (VPC) is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: CRITICAL
- **Description**: ElastiCache clusters must be deployed in a VPC.
- **Rationale**: Provides network isolation for caching layer.
- **Recommendation**: Migrate non-VPC clusters to VPC deployment.

### 5.8: Ensure Authentication and Access Control is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Configure Redis AUTH token for ElastiCache Redis clusters.
- **Rationale**: Prevents unauthorized access to cached data.
- **Recommendation**: Enable AUTH and use strong, rotated passwords.

### 5.6: Ensure Monitoring and Logging is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable slow log delivery to CloudWatch Logs.
- **Rationale**: Helps identify performance issues and potential security concerns.
- **Recommendation**: Configure slow log threshold and CloudWatch integration.

## Section 7: Amazon DocumentDB

Amazon DocumentDB is a MongoDB-compatible document database service.

### 7.3: Ensure Encryption at Rest is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: DocumentDB clusters should have encryption at rest enabled.
- **Rationale**: Protects document data from unauthorized access.
- **Impact**: Requires creating new encrypted cluster and migrating data.

### 7.4: Ensure Encryption in Transit is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: DocumentDB should enforce TLS for client connections.
- **Rationale**: Protects data during transmission.
- **Recommendation**: Enable TLS in cluster parameter group.

### 7.6: Ensure Audit Logging is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable audit logging and export to CloudWatch Logs.
- **Rationale**: Provides compliance audit trails.
- **Recommendation**: Enable audit logs in parameter group and configure log export.

### 7.9: Ensure to Implement Backup and Disaster Recovery
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Configure backup retention period (minimum 7 days).
- **Rationale**: Ensures data recovery capability.
- **Recommendation**: Set retention period based on RTO/RPO requirements.

## Section 9: Amazon Neptune

Amazon Neptune is a fully managed graph database service.

### 9.2: Ensure Data at Rest is Encrypted
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Neptune clusters should have encryption at rest enabled.
- **Rationale**: Protects graph data from unauthorized access.
- **Recommendation**: Enable encryption during cluster creation.

### 9.3: Ensure Data in Transit is Encrypted
- **Level**: 1
- **Type**: Manual
- **Severity**: HIGH
- **Description**: Neptune should enforce SSL/TLS for client connections.
- **Rationale**: Protects data during transmission.
- **Recommendation**: Configure applications to use SSL/TLS connections.

### 9.4: Ensure Authentication and Access Control is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Enable IAM database authentication for Neptune.
- **Rationale**: Uses IAM roles instead of database passwords.
- **Recommendation**: Enable IAM auth and configure IAM policies for database access.

### 9.5: Ensure Audit Logging is Enabled
- **Level**: 1
- **Type**: Manual
- **Severity**: MEDIUM
- **Description**: Export Neptune audit logs to CloudWatch Logs.
- **Rationale**: Provides audit trails for compliance.
- **Recommendation**: Enable audit log export in cluster configuration.

## Running CIS Database Services Checks

### Scan with All Benchmarks (Default)

```bash
# Run all three CIS benchmarks (Foundations, Compute, Database Services)
cloudauditor scan aws

# With specific region
cloudauditor scan aws --region us-west-2

# With real AWS credentials
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

- **CRITICAL**: Immediate action required (e.g., database exposed to internet, no VPC)
- **HIGH**: Urgent action required (e.g., no encryption, no SSL/TLS enforcement)
- **MEDIUM**: Should be addressed in timely manner (e.g., logging not enabled, short backup retention)
- **LOW**: Should be reviewed and addressed (e.g., minor configuration issues)

### Sample Output

```json
{
  "check_id": "3.5",
  "title": "RDS Instance Not Encrypted at Rest",
  "severity": "HIGH",
  "status": "FAILED",
  "resource_id": "rds-mysql-prod-db",
  "description": "RDS instance 'rds-mysql-prod-db' does not have encryption at rest enabled.",
  "recommendation": "Enable encryption at rest for RDS instance using AWS KMS. Requires creating a snapshot, copying with encryption, and restoring.",
  "compliance_standard": "CIS AWS Database Services Benchmark v1.0.0",
  "region": "us-east-1"
}
```

## Integration with Other Benchmarks

CloudAuditor runs all three CIS benchmarks simultaneously:

```json
{
  "compliance_standards": [
    "CIS AWS Foundations Benchmark v6.0.0",
    "CIS AWS Compute Services Benchmark v1.1.0",
    "CIS AWS Database Services Benchmark v1.0.0"
  ],
  "summary": {
    "total_checks": 57,
    "foundations": 15,
    "compute": 14,
    "databases": 28
  }
}
```

## Required AWS Permissions

To run all CIS Database Services checks with real AWS credentials, the following permissions are required:

### Aurora & RDS Permissions
- `rds:DescribeDBClusters`
- `rds:DescribeDBInstances`
- `rds:DescribeDBClusterParameterGroups`
- `rds:DescribeDBParameters`
- `rds:ListTagsForResource`

### DynamoDB Permissions
- `dynamodb:DescribeTable`
- `dynamodb:ListTables`
- `dynamodb:DescribeContinuousBackups`

### ElastiCache Permissions
- `elasticache:DescribeCacheClusters`
- `elasticache:DescribeReplicationGroups`
- `elasticache:DescribeCacheParameters`

### DocumentDB Permissions
- `rds:DescribeDBClusters` (DocumentDB uses RDS APIs)
- `rds:DescribeDBClusterParameters`

### Neptune Permissions
- `neptune-db:DescribeDBClusters`
- `neptune-db:DescribeDBInstances`

### Recommended IAM Policy

For read-only security scanning, use:
- `SecurityAudit` (AWS managed policy with comprehensive read-only access)

Or create a custom policy with specific permissions listed above.

## Service Coverage

### Implemented (6 services, 28 checks)
- ✅ Amazon Aurora
- ✅ Amazon RDS
- ✅ Amazon DynamoDB
- ✅ Amazon ElastiCache
- ✅ Amazon DocumentDB
- ✅ Amazon Neptune

### Not Yet Implemented (5 services)
- ⏳ Amazon MemoryDB for Redis (Section 6)
- ⏳ Amazon Keyspaces (Section 8)
- ⏳ Amazon Timestream (Section 10)
- ⏳ Amazon QLDB (Section 11)

These services can be added in future releases following the same checker pattern.

## Common Database Security Issues

Based on CIS benchmark requirements, the most common database security issues include:

1. **Encryption at Rest Not Enabled** (HIGH)
   - Affects: Aurora, RDS, DynamoDB, ElastiCache, DocumentDB, Neptune
   - Impact: Data vulnerable if storage media is compromised
   - Fix: Enable encryption using AWS KMS

2. **Encryption in Transit Not Enforced** (HIGH)
   - Affects: All database services
   - Impact: Data vulnerable to man-in-the-middle attacks
   - Fix: Configure SSL/TLS enforcement

3. **Databases Not in VPC** (CRITICAL)
   - Affects: RDS, ElastiCache
   - Impact: Lack of network isolation
   - Fix: Migrate to VPC deployment

4. **Audit Logging Not Enabled** (MEDIUM)
   - Affects: All database services
   - Impact: Limited compliance and forensic capabilities
   - Fix: Enable logging and export to CloudWatch

5. **Short Backup Retention** (MEDIUM)
   - Affects: Aurora, RDS, DocumentDB
   - Impact: Limited recovery window
   - Fix: Configure retention period ≥ 7 days

## Best Practices

1. **Enable Encryption by Default**
   - Use AWS KMS customer managed keys (CMK)
   - Enable both at-rest and in-transit encryption
   - Rotate KMS keys annually

2. **Implement Defense in Depth**
   - Use VPCs for network isolation
   - Configure security groups with least privilege
   - Use VPC endpoints where available
   - Enable IAM database authentication

3. **Enable Comprehensive Logging**
   - CloudTrail for control plane operations
   - Database audit logs for data plane operations
   - Export logs to CloudWatch for analysis
   - Set up alerts for suspicious activity

4. **Automate Security Operations**
   - Use AWS Secrets Manager for credential rotation
   - Enable auto minor version upgrades
   - Configure automated backups
   - Implement automated compliance scanning

5. **Regular Security Reviews**
   - Scan with CloudAuditor regularly
   - Review and remediate findings by severity
   - Conduct periodic access reviews
   - Update security configurations as services evolve

## References

- [CIS AWS Database Services Benchmark v1.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Database Security Best Practices](https://aws.amazon.com/products/databases/)
- [AWS Security Hub - Database Services Controls](https://docs.aws.amazon.com/securityhub/)

## Contributing

To add more database service checkers or additional checks:

1. Create a new checker module in `cloudauditor/providers/aws_databases/`
2. Inherit from `BaseDatabaseChecker`
3. Implement check methods following CIS benchmark
4. Add mock findings for testing
5. Update `__init__.py` to export new checker
6. Update AWS scanner to include new checker
7. Add documentation to this file

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

This implementation is provided under the MIT License. See [LICENSE](LICENSE) for details.
