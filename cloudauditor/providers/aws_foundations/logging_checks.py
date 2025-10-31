"""
CIS AWS Foundations Benchmark - Logging Checks (Section 4)
Critical logging and monitoring configuration checks
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class LoggingFoundationsChecker(BaseAWSChecker):
    """Checker for logging security - CIS AWS Foundations Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all logging foundation checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_cloudtrail_enabled())
            findings.extend(self.check_cloudtrail_log_validation())
            findings.extend(self.check_cloudtrail_encryption())
            findings.extend(self.check_vpc_flow_logging())
            findings.extend(self.check_kms_rotation())
            findings.extend(self.check_s3_object_write_events())
            findings.extend(self.check_s3_object_read_events())
            findings.extend(self.check_aws_config_enabled())
            findings.extend(self.check_cloudtrail_bucket_access_logging_manual())
            findings.extend(self.check_cloudtrail_bucket_mfa_delete_manual())
            findings.extend(self.check_unauthorized_api_calls_metric_manual())
            findings.extend(self.check_console_no_mfa_metric_manual())
            findings.extend(self.check_root_usage_metric_manual())
            findings.extend(self.check_iam_policy_change_metric_manual())
            findings.extend(self.check_cloudtrail_config_change_metric_manual())
            findings.extend(self.check_console_failed_auth_metric_manual())
            findings.extend(self.check_kms_disable_or_delete_metric_manual())
            findings.extend(self.check_s3_bucket_policy_change_metric_manual())
            findings.extend(self.check_aws_config_change_metric_manual())
            findings.extend(self.check_nacl_change_metric_manual())
            findings.extend(self.check_network_gateway_change_metric_manual())
            findings.extend(self.check_route_table_change_metric_manual())
            findings.extend(self.check_vpc_change_metric_manual())
            findings.extend(self.check_organizations_change_metric_manual())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.ERROR",
                    title="Error Running Logging Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="logging",
                    description=f"Failed to run logging checks: {str(e)}",
                    recommendation="Verify AWS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_cloudtrail_config_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.5: Ensure CloudTrail configuration changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
        findings.append(
            self.create_finding(
                check_id="5.5",
                title="CloudTrail Configuration Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for CloudTrail configuration changes.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <cloudtrail-cfg-changes-metric> --metric-transformations metricName=<cloudtrail-cfg-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <cloudtrail-cfg-changes-alarm> --metric-name <cloudtrail-cfg-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_console_failed_auth_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.6: Ensure AWS Management Console authentication failures are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
        findings.append(
            self.create_finding(
                check_id="5.6",
                title="Console Authentication Failures Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for failed ConsoleLogin events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <console-signin-failure-metric> --metric-transformations metricName=<console-signin-failure-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <console-signin-failure-alarm> --metric-name <console-signin-failure-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_kms_disable_or_delete_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.7: Ensure disabling or scheduled deletion of customer created CMKs is monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }'
        findings.append(
            self.create_finding(
                check_id="5.7",
                title="KMS Disable/Schedule Deletion Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for KMS DisableKey and ScheduleKeyDeletion events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <disable-or-delete-cmk-changes-metric> --metric-transformations metricName=<disable-or-delete-cmk-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <disable-or-delete-cmk-changes-alarm> --metric-name <disable-or-delete-cmk-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_s3_bucket_policy_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.8: Ensure S3 bucket policy changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
        findings.append(
            self.create_finding(
                check_id="5.8",
                title="S3 Bucket Policy Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for S3 bucket policy change events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <s3-bucket-policy-changes-metric> --metric-transformations metricName=<s3-bucket-policy-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <s3-bucket-policy-changes-alarm> --metric-name <s3-bucket-policy-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_aws_config_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.9: Ensure AWS Config configuration changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }'
        findings.append(
            self.create_finding(
                check_id="5.9",
                title="AWS Config Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for AWS Config configuration changes.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <aws-config-changes-metric> --metric-transformations metricName=<aws-config-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <aws-config-changes-alarm> --metric-name <aws-config-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_nacl_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.11: Ensure Network ACL changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
        findings.append(
            self.create_finding(
                check_id="5.11",
                title="Network ACL Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for Network ACL change events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <nacl-changes-metric> --metric-transformations metricName=<nacl-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <nacl-changes-alarm> --metric-name <nacl-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_network_gateway_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.12: Ensure changes to network gateways are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
        findings.append(
            self.create_finding(
                check_id="5.12",
                title="Network Gateway Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for network gateway changes.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <network-gw-changes-metric> --metric-transformations metricName=<network-gw-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <network-gw-changes-alarm> --metric-name <network-gw-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_route_table_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.13: Ensure route table changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventSource = ec2.amazonaws.com) && ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
        findings.append(
            self.create_finding(
                check_id="5.13",
                title="Route Table Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for route table change events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <route-table-changes-metric> --metric-transformations metricName=<route-table-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <route-table-changes-alarm> --metric-name <route-table-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_vpc_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.14: Ensure VPC changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
        findings.append(
            self.create_finding(
                check_id="5.14",
                title="VPC Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for VPC change events and peering operations.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <vpc-changes-metric> --metric-transformations metricName=<vpc-changes-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <vpc-changes-alarm> --metric-name <vpc-changes-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def check_organizations_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.15: Ensure AWS Organizations changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        pattern = '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'
        findings.append(
            self.create_finding(
                check_id="5.15",
                title="AWS Organizations Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter and alarm exist for AWS Organizations management events.",
                recommendation=(
                    "Create filter and alarm. Example:\n"
                    f"aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <organizations-changes> --metric-transformations metricName=<organizations-changes>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{pattern}'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <organizations-changes> --metric-name <organizations-changes> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}",
                evidence={"LogGroup": log_group, "FilterPattern": pattern},
            )
        )
        return findings

    def _cloudtrail_log_group_from_trails(self):
        """Helper: get active multi-region trail log group name if present."""
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                if t.get("IsMultiRegionTrail") and t.get("CloudWatchLogsLogGroupArn"):
                    arn = t.get("CloudWatchLogsLogGroupArn")
                    # arn:aws:logs:<region>:<account>:log-group:<group-name>:*
                    parts = arn.split(":log-group:")
                    if len(parts) > 1:
                        group_part = parts[1]
                        log_group = group_part.split(":*")[0]
                        return t.get("Name"), log_group
        except Exception:
            pass
        return None, None

    def check_unauthorized_api_calls_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.1: Ensure unauthorized API calls are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        trail_name, log_group = self._cloudtrail_log_group_from_trails()
        logs_client = self.session.client("logs", region_name=self.region)
        cw = self.session.client("cloudwatch", region_name=self.region)

        metric_name = None
        evidence_filters = {}
        evidence_alarms = {}
        try:
            if log_group:
                mf = logs_client.describe_metric_filters(logGroupName=log_group)
                evidence_filters = mf
                # look for required pattern
                for f in mf.get("metricFilters", []):
                    patt = f.get("filterPattern", "")
                    if "UnauthorizedOperation" in patt or "AccessDenied" in patt:
                        # capture metric name
                        transforms = f.get("metricTransformations", [])
                        if transforms:
                            metric_name = transforms[0].get("metricName")
                        break
            if metric_name:
                alarms = cw.describe_alarms()
                # filter local evidence list
                matched = [a for a in alarms.get("MetricAlarms", []) if a.get("MetricName") == metric_name]
                evidence_alarms = {"MatchedMetricAlarms": matched}
        except Exception:
            pass

        findings.append(
            self.create_finding(
                check_id="5.1",
                title="Unauthorized API Calls Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description=(
                    "Verify CloudWatch Logs metric filter and alarm exist for unauthorized API calls pattern on the CloudTrail log group."
                ),
                recommendation=(
                    "Create metric filter and alarm. Example:\n"
                    "aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <unauthorized-api-calls-metric> --metric-transformations metricName=unauthorized_api_calls_metric,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern \"{ ($.errorCode =\\\"*UnauthorizedOperation\\\") || ($.errorCode =\\\"AccessDenied*\\\") && ($.sourceIPAddress!=\\\"delivery.logs.amazonaws.com\\\") && ($.eventName!=\\\"HeadBucket\\\") }\"\n"
                    "aws cloudwatch put-metric-alarm --alarm-name unauthorized_api_calls_alarm --metric-name unauthorized_api_calls_metric --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    f"aws cloudtrail describe-trails; aws cloudtrail get-trail-status --name {trail_name or '<trail>'};\n"
                    f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'};\n"
                    f"aws cloudwatch describe-alarms --query \"MetricAlarms[?MetricName=='{metric_name or '<metric>'}']\""
                ),
                evidence={"LogGroup": log_group, **(evidence_filters or {}), **(evidence_alarms or {})},
            )
        )
        return findings

    def check_console_no_mfa_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.2: Ensure management console sign-in without MFA is monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        trail_name, log_group = self._cloudtrail_log_group_from_trails()
        findings.append(
            self.create_finding(
                check_id="5.2",
                title="Console Sign-in Without MFA Metric/Alarm Review (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description=(
                    "Verify a metric filter exists for ConsoleLogin without MFA and an alarm with an active SNS subscription."
                ),
                recommendation=(
                    "Create metric filter and alarm. Examples:\n"
                    "aws logs describe-metric-filters --log-group-name <trail-log-group-name>\n"
                    "aws logs put-metric-filter --log-group-name <trail-log-group-name> --filter-name <no-mfa-console-signin-metric> --metric-transformations metricName=<no-mfa-console-signin-metric>,metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }'\n"
                    "aws cloudwatch put-metric-alarm --alarm-name <no-mfa-console-signin-alarm> --metric-name <no-mfa-console-signin-metric> --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions <sns-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    f"aws cloudtrail describe-trails; aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}"
                ),
                evidence={"LogGroup": log_group},
            )
        )
        return findings

    def check_root_usage_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.3: Ensure usage of the 'root' account is monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        findings.append(
            self.create_finding(
                check_id="5.3",
                title="Root Account Usage Metric/Alarm Review (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter exists for root usage events and an alarm with SNS subscribers.",
                recommendation=(
                    "Add metric filter and alarm for: { $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}"
                ),
                evidence={"LogGroup": log_group},
            )
        )
        return findings

    def check_iam_policy_change_metric_manual(self) -> List[Dict[str, Any]]:
        """
        5.4: Ensure IAM policy changes are monitored (Manual)
        """
        findings: List[Dict[str, Any]] = []
        _, log_group = self._cloudtrail_log_group_from_trails()
        findings.append(
            self.create_finding(
                check_id="5.4",
                title="IAM Policy Change Metric/Alarm Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=log_group or "cloudwatch-logs",
                description="Verify metric filter exists for IAM policy change events and an alarm is configured.",
                recommendation=(
                    "Add metric filter and alarm for policy change events (Delete*/Put*/Attach*/Detach*). See CIS-provided filterPattern in guidance."
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    f"aws logs describe-metric-filters --log-group-name {log_group or '<log-group>'}"
                ),
                evidence={"LogGroup": log_group},
            )
        )
        return findings

    def check_cloudtrail_bucket_mfa_delete_manual(self) -> List[Dict[str, Any]]:
        """
        4.x (Manual): Ensure the S3 bucket used for CloudTrail has Versioning enabled and MFA Delete enabled
        Level: 1 | Type: Manual | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        # This is a manual validation because MFA Delete state often requires root and cannot be queried in some contexts.
        # Provide commands and indicative evidence to guide the reviewer.
        findings.append(
            self.create_finding(
                check_id="4.M1",
                title="CloudTrail S3 Bucket MFA Delete and Versioning Requires Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="s3:cloudtrail-logs-bucket",
                description=(
                    "Verify that the CloudTrail destination S3 bucket has Versioning enabled and MFA Delete enabled."
                ),
                recommendation=(
                    "Enable Versioning and MFA Delete on the CloudTrail S3 bucket. Example: "
                    "aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled "
                    "--mfa 'arn:aws:iam::<account-id>:mfa/root-account-mfa-device <mfa-code>'"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    "aws s3api get-bucket-versioning --bucket <cloudtrail-bucket>"
                ),
                evidence={"Status": "Enabled", "MFADelete": "Disabled"}
            )
        )
        return findings

    def check_cloudtrail_enabled(self) -> List[Dict[str, Any]]:
        """
        4.1: Ensure CloudTrail is enabled in all regions
        Level: 1 | Type: Manual | HIGH
        """
        findings = []
        try:
            cloudtrail = self.session.client("cloudtrail", region_name=self.region)
            trails = cloudtrail.describe_trails()

            multi_region_trails = [
                trail for trail in trails.get("trailList", [])
                if trail.get("IsMultiRegionTrail", False) and trail.get("IsLogging", False)
            ]

            if len(multi_region_trails) == 0:
                finding = self.create_finding(
                    check_id="4.1",
                    title="CloudTrail Not Enabled in All Regions",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="cloudtrail",
                    description="No multi-region CloudTrail trail is enabled and logging.",
                    recommendation=(
                        "Create and enable a multi‑region trail with log file validation and KMS CMK: "
                        "1) aws cloudtrail create-trail --name <trail> --is-multi-region-trail --enable-log-file-validation "
                        "--kms-key-id <kms-key-arn> --s3-bucket-name <bucket> "
                        "2) aws cloudtrail start-logging --name <trail>"
                    ),
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command=f"aws cloudtrail describe-trails --region {self.region} --query 'trailList[?IsMultiRegionTrail==`true` && IsLogging==`true`]'",
                    evidence=trails
                )
                findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.1",
                    title="Unable to Check CloudTrail",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="cloudtrail",
                    description=f"Could not verify CloudTrail: {str(e)}",
                    recommendation="Verify CloudTrail permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_cloudtrail_log_validation(self) -> List[Dict[str, Any]]:
        """
        4.2: Ensure CloudTrail log file validation is enabled
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            cloudtrail = self.session.client("cloudtrail", region_name=self.region)
            trails = cloudtrail.describe_trails()

            for trail in trails.get("trailList", []):
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", "")

                status = cloudtrail.get_trail_status(Name=trail_name)
                log_file_validation = trail.get("LogFileValidationEnabled", False)

                if status.get("IsLogging", False) and not log_file_validation:
                    finding = self.create_finding(
                        check_id="4.2",
                        title="CloudTrail Log File Validation Not Enabled",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=trail_arn,
                        description=f"CloudTrail trail '{trail_name}' does not have log file validation enabled.",
                        recommendation=(
                            "Enable CloudTrail log file validation: "
                            "aws cloudtrail update-trail --name <trail> --enable-log-file-validation"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws cloudtrail get-trail-status --name {trail_name}",
                        evidence={"IsLogging": status.get("IsLogging"), "LogFileValidationEnabled": log_file_validation}
                    )
                    findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.2",
                    title="Unable to Check CloudTrail Log Validation",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="cloudtrail",
                    description=f"Could not verify log validation: {str(e)}",
                    recommendation="Verify CloudTrail permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_cloudtrail_encryption(self) -> List[Dict[str, Any]]:
        """
        4.5: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            cloudtrail = self.session.client("cloudtrail", region_name=self.region)
            trails = cloudtrail.describe_trails()

            for trail in trails.get("trailList", []):
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", "")
                kms_key_id = trail.get("KmsKeyId")

                if not kms_key_id:
                    finding = self.create_finding(
                        check_id="4.5",
                        title="CloudTrail Logs Not Encrypted with KMS",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=trail_arn,
                        description=f"CloudTrail trail '{trail_name}' does not use KMS encryption.",
                        recommendation=(
                            "Encrypt CloudTrail with a customer-managed CMK: "
                            "aws cloudtrail update-trail --name <trail> --kms-key-id <kms-key-arn>"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws cloudtrail describe-trails --trail-name-list {trail_name} --query 'trailList[0].KmsKeyId'",
                        evidence={"KmsKeyId": kms_key_id, "TrailName": trail_name}
                    )
                    findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.5",
                    title="Unable to Check CloudTrail Encryption",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="cloudtrail",
                    description=f"Could not verify CloudTrail encryption: {str(e)}",
                    recommendation="Verify CloudTrail permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_aws_config_enabled(self) -> List[Dict[str, Any]]:
        """
        4.3: Ensure AWS Config is enabled in this region (Automated)
        Level: 2 | Type: Automated | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            cfg = self.session.client("config", region_name=self.region)
            recorders = cfg.describe_configuration_recorders()
            statuses = cfg.describe_configuration_recorder_status()

            has_recorder = len(recorders.get("ConfigurationRecorders", [])) > 0
            all_supported = False
            include_globals = False
            recorder_name = None

            if has_recorder:
                rec = recorders["ConfigurationRecorders"][0]
                recorder_name = rec.get("name")
                rg = rec.get("recordingGroup", {})
                all_supported = rg.get("allSupported", False)
                include_globals = rg.get("includeGlobalResourceTypes", False)

            is_recording = any(s.get("recording") for s in statuses.get("ConfigurationRecorderStatuses", []))

            if (not has_recorder) or (not all_supported) or (not is_recording):
                findings.append(
                    self.create_finding(
                        check_id="4.3",
                        title="AWS Config Not Fully Enabled (This Region)",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=f"config:{self.region}",
                        description=(
                            "AWS Config recorder not present, not recording all resources, or not actively recording."
                        ),
                        recommendation=(
                            "Create/enable a recorder for all resources and include globals in one region. Commands:\n"
                            "aws configservice put-configuration-recorder --configuration-recorder name=<name>,roleARN=<role-arn> --recording-group allSupported=true,includeGlobalResourceTypes=true\n"
                            "aws configservice put-delivery-channel --delivery-channel file://<delivery-channel-file>.json\n"
                            "aws configservice start-configuration-recorder --configuration-recorder-name <name>"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=(
                            f"aws configservice describe-configuration-recorders --region {self.region};\n"
                            f"aws configservice describe-configuration-recorder-status --region {self.region}"
                        ),
                        evidence={
                            "RecorderName": recorder_name,
                            "AllSupported": all_supported,
                            "IncludeGlobalResourceTypes": include_globals,
                            "IsRecording": is_recording,
                        },
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="4.3",
                        title="AWS Config Enabled (This Region)",
                        severity="INFO",
                        status="PASSED",
                        resource_id=f"config:{self.region}",
                        description="AWS Config recorder is present and actively recording.",
                        recommendation="Ensure delivery channel is configured and include globals in one region.",
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=(
                            f"aws configservice describe-configuration-recorders --region {self.region};\n"
                            f"aws configservice describe-configuration-recorder-status --region {self.region}"
                        ),
                        evidence={
                            "RecorderName": recorder_name,
                            "AllSupported": all_supported,
                            "IncludeGlobalResourceTypes": include_globals,
                            "IsRecording": is_recording,
                        },
                    )
                )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.3",
                    title="Unable to Check AWS Config",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="config",
                    description=f"Could not verify AWS Config: {str(e)}",
                    recommendation="Verify AWS Config permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_cloudtrail_bucket_access_logging_manual(self) -> List[Dict[str, Any]]:
        """
        4.4: Ensure that server access logging is enabled on the CloudTrail S3 bucket (Manual)
        Level: 1 | Type: Manual | LOW
        """
        findings: List[Dict[str, Any]] = []
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            s3 = self.session.client("s3")
            trails = ct.describe_trails()
            for trail in trails.get("trailList", []):
                bucket = trail.get("S3BucketName")
                if not bucket:
                    continue
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket)
                    if not logging.get("LoggingEnabled"):
                        findings.append(
                            self.create_finding(
                                check_id="4.4",
                                title="CloudTrail S3 Bucket Logging Not Enabled (Manual)",
                                severity="LOW",
                                status="WARNING",
                                resource_id=f"s3://{bucket}",
                                description="Server access logging is not enabled on the CloudTrail destination bucket.",
                                recommendation=(
                                    "Enable server access logging on the CloudTrail bucket and target to a separate logging bucket.\n"
                                    f"aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status file://logging.json"
                                ),
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                command=f"aws cloudtrail describe-trails --region {self.region} --query 'trailList[*].S3BucketName'; aws s3api get-bucket-logging --bucket {bucket}",
                                evidence=logging,
                            )
                        )
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    def check_vpc_flow_logging(self) -> List[Dict[str, Any]]:
        """
        4.7: Ensure VPC flow logging is enabled in all VPCs
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            vpcs = ec2.describe_vpcs()

            for vpc in vpcs.get("Vpcs", []):
                vpc_id = vpc.get("VpcId", "")

                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )

                if len(flow_logs.get("FlowLogs", [])) == 0:
                    finding = self.create_finding(
                        check_id="4.7",
                        title="VPC Flow Logging Not Enabled",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=vpc_id,
                        description=f"VPC '{vpc_id}' does not have flow logging enabled.",
                        recommendation=(
                            "Enable VPC Flow Logs to CloudWatch Logs with an IAM role: "
                            "1) aws logs create-log-group --log-group-name /vpc/flow-logs/<vpc-id> "
                            "2) aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
                            "--traffic-type ALL --log-group-name /vpc/flow-logs/<vpc-id> --deliver-logs-permission-arn <iam-role-arn>"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws ec2 describe-flow-logs --filters Name=resource-id,Values={vpc_id}",
                        evidence=flow_logs
                    )
                    findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.7",
                    title="Unable to Check VPC Flow Logging",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="vpc",
                    description=f"Could not verify VPC flow logging: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_kms_rotation(self) -> List[Dict[str, Any]]:
        """
        4.6: Ensure rotation for customer-created symmetric CMKs is enabled
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            kms = self.session.client("kms", region_name=self.region)
            keys = kms.list_keys()

            for key in keys.get("Keys", []):
                key_id = key.get("KeyId", "")

                try:
                    key_metadata = kms.describe_key(KeyId=key_id)
                    key_manager = key_metadata.get("KeyMetadata", {}).get("KeyManager", "")

                    if key_manager == "CUSTOMER":
                        rotation_status = kms.get_key_rotation_status(KeyId=key_id)

                        if not rotation_status.get("KeyRotationEnabled", False):
                            finding = self.create_finding(
                                check_id="4.6",
                                title="KMS Key Rotation Not Enabled",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=key_id,
                                description=f"Customer-managed KMS key '{key_id}' does not have automatic rotation enabled.",
                                recommendation="Enable automatic key rotation for customer-managed KMS keys",
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                command=f"aws kms get-key-rotation-status --key-id {key_id}",
                                evidence=rotation_status
                            )
                            findings.append(finding)

                except Exception:
                    pass

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="4.6",
                    title="Unable to Check KMS Key Rotation",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="kms",
                    description=f"Could not verify KMS key rotation: {str(e)}",
                    recommendation="Verify KMS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def _trail_logs_s3_data_events_enabled(self, ct_client, trail_name: str, required_type: str) -> Dict[str, Any]:
        """Helper: inspect event selectors for S3 data events with required ReadWriteType (WriteOnly/ReadOnly)."""
        selectors = ct_client.get_event_selectors(TrailName=trail_name)
        event_selectors = selectors.get("EventSelectors", [])
        advanced = selectors.get("AdvancedEventSelectors")
        enabled = False
        evidence = {"EventSelectors": event_selectors, "AdvancedEventSelectors": advanced}

        # Advanced selectors can be complex; if present and includes S3 Object log-all, consider enabled
        if advanced:
            try:
                for aes in advanced:
                    for field_sel in aes.get("FieldSelectors", []):
                        if field_sel.get("Field") == "eventCategory":
                            if any(v.get("StartsWith") == "Data" or v.get("Equals") == ["Data"] for v in [field_sel]):
                                enabled = True
            except Exception:
                pass

        for es in event_selectors:
            rw = es.get("ReadWriteType", "All")
            data_resources = es.get("DataResources", [])
            s3_resources = [dr for dr in data_resources if dr.get("Type") == "AWS::S3::Object"]
            values = [v for dr in s3_resources for v in dr.get("Values", [])]
            # Accept arn:aws:s3 or specific bucket ARNs
            if s3_resources and values and (rw == required_type or rw == "All"):
                enabled = True
        evidence["EvaluatedReadWriteType"] = required_type
        evidence["Enabled"] = enabled
        return {"enabled": enabled, "evidence": evidence}

    def check_s3_object_write_events(self) -> List[Dict[str, Any]]:
        """
        4.8: Ensure that object-level logging for write events is enabled for S3 buckets (Automated)
        Level: 2 | Type: Automated | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails()
            for trail in trails.get("trailList", []):
                trail_name = trail.get("Name")
                trail_arn = trail.get("TrailARN")
                if not trail_name:
                    continue
                # Check multi-region
                trail_desc = ct.get_trail(Name=trail_name).get("Trail", {})
                is_multi = trail_desc.get("IsMultiRegionTrail", False)
                res = self._trail_logs_s3_data_events_enabled(ct, trail_name, required_type="WriteOnly")
                if not (is_multi and res.get("enabled")):
                    findings.append(
                        self.create_finding(
                            check_id="4.8",
                            title="S3 Object-level Logging for Write Events Not Enabled",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=trail_arn or trail_name,
                            description=(
                                "CloudTrail trail does not have multi-region enabled and/or is not logging S3 object write (data) events."
                            ),
                            recommendation=(
                                "Enable multi-region and S3 data event logging (write-only) for the trail. Example:\n"
                                'aws cloudtrail put-event-selectors --region <region> --trail-name <trail> --event-selectors '\
                                '\'[{"ReadWriteType":"WriteOnly","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]\''
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=(
                                f"aws cloudtrail get-trail --name {trail_name} --region {self.region} --query 'Trail.IsMultiRegionTrail';\n"
                                f"aws cloudtrail get-event-selectors --region {self.region} --trail-name {trail_name} --query EventSelectors[*].DataResources[]"
                            ),
                            evidence={"IsMultiRegionTrail": is_multi, **res.get("evidence", {})},
                        )
                    )
        except Exception:
            pass
        return findings

    def check_s3_object_read_events(self) -> List[Dict[str, Any]]:
        """
        4.9: Ensure that object-level logging for read events is enabled for S3 buckets (Automated)
        Level: 2 | Type: Automated | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails()
            for trail in trails.get("trailList", []):
                trail_name = trail.get("Name")
                trail_arn = trail.get("TrailARN")
                if not trail_name:
                    continue
                trail_desc = ct.get_trail(Name=trail_name).get("Trail", {})
                is_multi = trail_desc.get("IsMultiRegionTrail", False)
                res = self._trail_logs_s3_data_events_enabled(ct, trail_name, required_type="ReadOnly")
                if not (is_multi and res.get("enabled")):
                    findings.append(
                        self.create_finding(
                            check_id="4.9",
                            title="S3 Object-level Logging for Read Events Not Enabled",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=trail_arn or trail_name,
                            description=(
                                "CloudTrail trail does not have multi-region enabled and/or is not logging S3 object read (data) events."
                            ),
                            recommendation=(
                                "Enable multi-region and S3 data event logging (read-only) for the trail. Example:\n"
                                'aws cloudtrail put-event-selectors --region <region> --trail-name <trail> --event-selectors '\
                                '\'[{"ReadWriteType":"ReadOnly","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]\''
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=(
                                f"aws cloudtrail get-trail --name {trail_name} --region {self.region} --query 'Trail.IsMultiRegionTrail';\n"
                                f"aws cloudtrail get-event-selectors --region {self.region} --trail-name {trail_name} --query EventSelectors[*].DataResources[]"
                            ),
                            evidence={"IsMultiRegionTrail": is_multi, **res.get("evidence", {})},
                        )
                    )
        except Exception:
            pass
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="4.1",
                title="CloudTrail Not Enabled in All Regions",
                severity="HIGH",
                status="FAILED",
                resource_id="cloudtrail",
                description="No multi-region CloudTrail trail is enabled.",
                recommendation=(
                    "Create and enable a multi‑region trail with log file validation and KMS CMK: "
                    "aws cloudtrail create-trail --name <trail> --is-multi-region-trail --enable-log-file-validation "
                    "--kms-key-id <kms-key-arn> --s3-bucket-name <bucket>; aws cloudtrail start-logging --name <trail>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true` && IsLogging==`true`]'",
                evidence={"trailList": []}
            ),
            self.create_finding(
                check_id="4.5",
                title="CloudTrail Logs Not Encrypted with KMS",
                severity="MEDIUM",
                status="FAILED",
                resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/default",
                description="CloudTrail trail does not use KMS encryption.",
                recommendation=(
                    "Encrypt CloudTrail with a customer-managed CMK: "
                    "aws cloudtrail update-trail --name <trail> --kms-key-id <kms-key-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws cloudtrail describe-trails --trail-name-list default --query 'trailList[0].KmsKeyId'",
                evidence={"KmsKeyId": None, "TrailName": "default"}
            ),
            self.create_finding(
                check_id="4.7",
                title="VPC Flow Logging Not Enabled",
                severity="MEDIUM",
                status="FAILED",
                resource_id="vpc-0123456789abcdef0",
                description="VPC does not have flow logging enabled.",
                recommendation=(
                    "Enable VPC Flow Logs to CloudWatch Logs with an IAM role: "
                    "aws logs create-log-group --log-group-name /vpc/flow-logs/<vpc-id>; "
                    "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL "
                    "--log-group-name /vpc/flow-logs/<vpc-id> --deliver-logs-permission-arn <iam-role-arn>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws ec2 describe-flow-logs --filters Name=resource-id,Values=vpc-0123456789abcdef0",
                evidence={"FlowLogs": []}
            ),
        ]
