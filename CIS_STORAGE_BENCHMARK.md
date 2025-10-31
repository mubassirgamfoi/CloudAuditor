# CIS AWS Storage Services Benchmark v1.0.0

This document outlines the implementation of the **CIS AWS Storage Services Benchmark v1.0.0** in CloudAuditor CLI.

## Overview

The CIS AWS Storage Services Benchmark v1.0.0 provides prescriptive guidance for configuring security options for AWS storage services. This benchmark covers:

- **AWS Backup** - Managed backup service for AWS resources
- **Amazon EBS** - Elastic Block Store for EC2 instances
- **Amazon EFS** - Elastic File System for shared storage
- **Amazon FSx** - Fully managed file systems (Lustre, Windows, NetApp ONTAP)
- **Amazon S3** - Simple Storage Service for object storage
- **AWS Elastic Disaster Recovery** - Disaster recovery service

## Implementation Details

### Directory Structure

```
cloudauditor/providers/aws_storage/
├── __init__.py
├── base_checker.py
├── backup_checks.py
├── ebs_checks.py
├── efs_checks.py
├── fsx_checks.py
├── s3_checks.py
└── edr_checks.py
```

### Check Categories

#### 1. AWS Backup (6 checks)
- **1.1** AWS Storage Backups (Manual)
- **1.2** Ensure securing AWS Backups (Manual)
- **1.3** Ensure to create backup template and name (Manual)
- **1.4** Ensure to create AWS IAM Policies (Manual)
- **1.5** Ensure to create IAM roles for Backup (Manual)
- **1.6** Ensure AWS Backup with Service Linked Roles (Manual)

#### 2. Amazon EBS (13 checks)
- **2.1** Ensure creating EC2 instance with EBS (Manual)
- **2.2** Ensure configuring Security Groups (Manual)
- **2.3** Ensure the proper configuration of EBS storage (Manual)
- **2.4** Ensure the creation of a new volume (Manual)
- **2.5** Ensure creating snapshots of EBS volumes (Manual)
- **2.6** Ensure Proper IAM Configuration for EC2 Instances (Manual)
- **2.7** Ensure creating IAM User (Manual)
- **2.8** Ensure the Creation of IAM Groups (Manual)
- **2.9** Ensure Granular Policy Creation (Manual)
- **2.10** Ensure Resource Access via Tag-based Policies (Manual)
- **2.11** Ensure Secure Password Policy Implementation (Manual)
- **2.12** Ensure Monitoring EC2 and EBS with CloudWatch (Manual)
- **2.13** Ensure creating an SNS subscription (Manual)

#### 3. Amazon EFS (12 checks)
- **3.1** EFS (Manual)
- **3.2** Ensure Implementation of EFS (Manual)
- **3.3** Ensure EFS and VPC Integration (Manual)
- **3.4** Ensure controlling Network access to EFS Services (Manual)
- **3.5** Ensure using Security Groups for VPC (Manual)
- **3.6** Ensure Secure Ports (Manual)
- **3.7** Ensure File-Level Access Control with Mount Targets (Manual)
- **3.8** Ensure managing mount target security groups (Manual)
- **3.9** Ensure using VPC endpoints - EFS (Manual)
- **3.10** Ensure managing AWS EFS access points (Manual)
- **3.11** Ensure accessing Points and IAM Policies (Manual)
- **3.12** Ensure configuring IAM for AWS Elastic Disaster Recovery (Manual)

#### 4. Amazon FSx (9 checks)
- **4.1** FSX (AWS Elastic File Cache) (Manual)
- **4.2** Amazon Elastic File Cache (Manual)
- **4.3** Ensure the creation of an FSX Bucket (Manual)
- **4.4** Ensure the creation of Elastic File Cache (Manual)
- **4.5** Ensure installation and configuration of Lustre Client (Manual)
- **4.6** Ensure EC2 Kernel compatibility with Lustre (Manual)
- **4.7** Ensure mounting FSx cache (Manual)
- **4.8** Ensure exporting cache to S3 (Manual)
- **4.9** Ensure cleaning up FSx Resources (Manual)

#### 5. Amazon S3 (3 checks)
- **5.1** Amazon Simple Storage Service (Manual)
- **5.2** Ensure direct data addition to S3 (Manual)
- **5.3** Ensure Storage Classes are Configured (Manual)

#### 6. AWS Elastic Disaster Recovery (13 checks)
- **6.1** Ensure Elastic Disaster Recovery is Configured (Manual)
- **6.2** Ensure AWS Disaster Recovery Configuration (Manual)
- **6.3** Ensure functionality of Endpoint Detection and Response (EDR) (Manual)
- **6.4** Ensure configuration of replication settings (Manual)
- **6.5** Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)
- **6.6** Ensure installation of the AWS Replication Agent (Manual)
- **6.7** Ensure proper configuration of the Launch Settings (Manual)
- **6.8** Ensure execution of a recovery drill (Manual)
- **6.9** Ensure Continuous Disaster Recovery Operations (Manual)
- **6.10** Ensure execution of a Disaster Recovery Failover (Manual)
- **6.11** Ensure execution of a failback (Manual)
- **6.12** Ensure CloudWatch Metrics for AWS EDR (Manual)
- **6.13** Ensure working of EDR (Manual)

## Usage

### Enable Storage Services Benchmark

The Storage Services benchmark is enabled by default. To disable it:

```python
from cloudauditor.providers.aws import AWSScanner

scanner = AWSScanner(
    region="us-east-1",
    enable_cis_storage=False  # Disable Storage Services benchmark
)
```

### Run Storage Services Checks

```python
# Run all benchmarks including Storage Services
results = scanner.scan()

# Filter for Storage Services findings
storage_findings = [
    finding for finding in results['findings']
    if finding.get('compliance_standard') == 'CIS AWS Storage Services Benchmark v1.0.0'
]
```

### CLI Usage

```bash
# Run all benchmarks including Storage Services
cloudauditor scan aws --region us-east-1

# Run with specific output format
cloudauditor scan aws --region us-east-1 --output json
```

## Key Features

### Automated Checks
- EBS volume encryption verification
- S3 bucket public access blocking
- EFS file system encryption
- FSx file cache encryption
- EDR configuration validation

### Manual Checks
- IAM policy and role configuration
- Security group configuration
- Network access controls
- Backup and disaster recovery procedures
- Storage class optimization

### Mock Data Support
All checkers support mock data for testing without AWS credentials:

```python
scanner = AWSScanner(use_mock=True)
results = scanner.scan()
```

## Compliance Standards

The Storage Services benchmark implements:

- **CIS AWS Storage Services Benchmark v1.0.0**
- **CIS Controls v7** (Implementation Groups 1, 2, 3)
- **CIS Controls v8** (Implementation Groups 1, 2, 3)

## Security Considerations

### Data Protection
- Encryption at rest and in transit
- Access control and IAM policies
- Backup and disaster recovery
- Data lifecycle management

### Network Security
- VPC configuration
- Security groups
- Network access controls
- VPC endpoints

### Monitoring and Logging
- CloudWatch metrics
- SNS notifications
- Audit logging
- Compliance reporting

## Error Handling

The implementation includes comprehensive error handling:

- Graceful fallback to mock data
- Detailed error logging
- User-friendly error messages
- Continuation of checks despite individual failures

## Future Enhancements

- Additional automated checks
- Integration with AWS Config rules
- Custom compliance frameworks
- Enhanced reporting capabilities

## References

- [CIS AWS Storage Services Benchmark v1.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Backup Documentation](https://docs.aws.amazon.com/aws-backup/)
- [Amazon EBS Documentation](https://docs.aws.amazon.com/ebs/)
- [Amazon EFS Documentation](https://docs.aws.amazon.com/efs/)
- [Amazon FSx Documentation](https://docs.aws.amazon.com/fsx/)
- [Amazon S3 Documentation](https://docs.aws.amazon.com/s3/)
- [AWS Elastic Disaster Recovery Documentation](https://docs.aws.amazon.com/drs/)
