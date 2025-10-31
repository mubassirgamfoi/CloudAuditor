"""
CIS AWS Compute Services Benchmark Checks
Organized by AWS service category
"""

from cloudauditor.providers.aws_checks.ec2_ami_checks import EC2AMIChecker
from cloudauditor.providers.aws_checks.ec2_ebs_checks import EC2EBSChecker
from cloudauditor.providers.aws_checks.ec2_general_checks import EC2GeneralChecker
from cloudauditor.providers.aws_checks.ecs_checks import ECSChecker
from cloudauditor.providers.aws_checks.lambda_checks import LambdaChecker

__all__ = [
    "EC2AMIChecker",
    "EC2EBSChecker",
    "EC2GeneralChecker",
    "ECSChecker",
    "LambdaChecker",
]
