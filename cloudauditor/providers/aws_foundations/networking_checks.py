"""
CIS AWS Foundations Benchmark - Networking Checks (Section 6)
Network security configuration checks
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class NetworkingFoundationsChecker(BaseAWSChecker):
    """Checker for networking security - CIS AWS Foundations Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all networking foundation checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_default_security_groups())
            findings.extend(self.check_security_group_ssh_rdp())
            findings.extend(self.check_imdsv2_enforcement())
            findings.extend(self.check_internet_gateway_exposure_manual())
            findings.extend(self.check_security_group_cifs())
            findings.extend(self.check_nacl_admin_ports())
            findings.extend(self.check_vpc_peering_least_access_manual())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.ERROR",
                    title="Error Running Networking Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="networking",
                    description=f"Failed to run networking checks: {str(e)}",
                    recommendation="Verify AWS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_security_group_cifs(self) -> List[Dict[str, Any]]:
        """
        6.1.2: Ensure CIFS (TCP 445) access is restricted to trusted networks (Automated)
        Level: 1 | Type: Automated | HIGH
        """
        findings: List[Dict[str, Any]] = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            sgs = ec2.describe_security_groups()

            for sg in sgs.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                for rule in sg.get("IpPermissions", []):
                    ip_protocol = rule.get("IpProtocol")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    if ip_protocol in ["-1", "tcp"] and from_port is not None and to_port is not None:
                        if from_port <= 445 <= to_port:
                            # IPv4
                            for ipr in rule.get("IpRanges", []):
                                if ipr.get("CidrIp") == "0.0.0.0/0":
                                    findings.append(
                                        self.create_finding(
                                            check_id="6.1.2",
                                            title="Security Group Allows CIFS (TCP 445) from Internet",
                                            severity="HIGH",
                                            status="FAILED",
                                            resource_id=sg_id,
                                            description=f"Security group '{sg_name}' ({sg_id}) allows TCP 445 from 0.0.0.0/0.",
                                            recommendation="Restrict CIFS (port 445) to trusted CIDRs only; remove 0.0.0.0/0 rule.",
                                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                            command=f"aws ec2 describe-security-groups --group-ids {sg_id} --query 'SecurityGroups[0].IpPermissions'",
                                            evidence={"FromPort": from_port, "ToPort": to_port, "CidrIp": "0.0.0.0/0", "Protocol": ip_protocol},
                                        )
                                    )
                            # IPv6
                            for ipr6 in rule.get("Ipv6Ranges", []):
                                if ipr6.get("CidrIpv6") == "::/0":
                                    findings.append(
                                        self.create_finding(
                                            check_id="6.1.2",
                                            title="Security Group Allows CIFS (TCP 445) from IPv6 Internet",
                                            severity="HIGH",
                                            status="FAILED",
                                            resource_id=sg_id,
                                            description=f"Security group '{sg_name}' ({sg_id}) allows TCP 445 from ::/0.",
                                            recommendation="Restrict CIFS (port 445) to trusted IPv6 ranges only; remove ::/0 rule.",
                                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                            command=f"aws ec2 describe-security-groups --group-ids {sg_id} --query 'SecurityGroups[0].IpPermissions'",
                                            evidence={"FromPort": from_port, "ToPort": to_port, "CidrIpv6": "::/0", "Protocol": ip_protocol},
                                        )
                                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.1.2",
                    title="Unable to Check CIFS Access",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="security-groups",
                    description=f"Could not verify CIFS access: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_nacl_admin_ports(self) -> List[Dict[str, Any]]:
        """
        6.2: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to SSH/RDP (Automated)
        Level: 1 | Type: Automated | HIGH
        """
        findings: List[Dict[str, Any]] = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            nacls = ec2.describe_network_acls()
            admin_ports = [22, 3389]
            for nacl in nacls.get("NetworkAcls", []):
                nacl_id = nacl.get("NetworkAclId", "")
                for entry in nacl.get("Entries", []):
                    if entry.get("Egress"):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue
                    cidr_v4 = entry.get("CidrBlock")
                    cidr_v6 = entry.get("Ipv6CidrBlock")
                    port_range = entry.get("PortRange") or {}
                    from_port = port_range.get("From")
                    to_port = port_range.get("To")
                    protocol = entry.get("Protocol")  # '6' tcp, '17' udp, '-1' all
                    # consider all protocols where range includes admin ports or all (-1)
                    if protocol in ["6", "17", "-1"]:
                        def port_matches():
                            if protocol == "-1" or from_port is None or to_port is None:
                                return True
                            return any(fp <= p <= tp for p in admin_ports for fp, tp in [(from_port, to_port)])

                        if port_matches() and (cidr_v4 == "0.0.0.0/0" or cidr_v6 == "::/0"):
                            findings.append(
                                self.create_finding(
                                    check_id="6.2",
                                    title="NACL Allows Admin Port from Internet",
                                    severity="HIGH",
                                    status="FAILED",
                                    resource_id=nacl_id,
                                    description="Network ACL has inbound allow rule for SSH/RDP or ALL from the Internet.",
                                    recommendation="Restrict NACL inbound rules to trusted CIDRs; remove 0.0.0.0/0 or ::/0 for admin ports.",
                                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                    command=f"aws ec2 describe-network-acls --network-acl-ids {nacl_id}",
                                    evidence={"CidrBlock": cidr_v4 or cidr_v6, "PortRange": port_range, "Protocol": protocol, "RuleAction": entry.get("RuleAction")},
                                )
                            )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.2",
                    title="Unable to Check NACL Admin Ports",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="network-acls",
                    description=f"Could not verify NACL rules: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_vpc_peering_least_access_manual(self) -> List[Dict[str, Any]]:
        """
        6.6: Ensure routing tables for VPC peering are 'least access' (Manual)
        Level: 2 | Type: Manual | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                findings.append(
                    self.create_finding(
                        check_id="6.6",
                        title="VPC Peering Route Tables Least Access Review (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id=vpc_id,
                        description=(
                            "Review route tables for peered connections and ensure routes are scoped to minimum required CIDRs."
                        ),
                        recommendation=(
                            "Use delete-route/create-route to remove broad routes and add specific CIDRs only for peering."
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=(
                            f"aws ec2 describe-route-tables --filter Name=vpc-id,Values={vpc_id} --query 'RouteTables[*].{RouteTableId:RouteTableId,Routes:Routes,Associations:Associations[*].SubnetId}'"
                        ),
                        evidence={"VpcId": vpc_id},
                    )
                )
        except Exception:
            pass

        return findings

    def check_internet_gateway_exposure_manual(self) -> List[Dict[str, Any]]:
        """
        6.M1 (Manual): Review VPC Internet Gateway exposure and route table associations
        Level: 1 | Type: Manual | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="6.M1",
                title="VPC Internet Gateway Exposure Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=f"ec2:{self.region}:internet-gateways",
                description=(
                    "Verify only intended public subnets route 0.0.0.0/0 to Internet Gateways; ensure private subnets do not."
                ),
                recommendation=(
                    "Audit route tables and detach unused Internet Gateways; ensure private subnets route through NAT Gateways only."
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    f"aws ec2 describe-internet-gateways --region {self.region}; "
                    f"aws ec2 describe-route-tables --region {self.region} --query 'RouteTables[].Routes[?DestinationCidrBlock==`0.0.0.0/0`]'"
                ),
                evidence={"routesToIGW": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0123456789abcdef0"}]}
            )
        )
        return findings

    def check_default_security_groups(self) -> List[Dict[str, Any]]:
        """
        6.5: Ensure the default security group of every VPC restricts all traffic
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            security_groups = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )

            for sg in security_groups.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                ingress_rules = sg.get("IpPermissions", [])
                egress_rules = sg.get("IpPermissionsEgress", [])

                if ingress_rules or egress_rules:
                    finding = self.create_finding(
                        check_id="6.5",
                        title="Default Security Group Allows Traffic",
                        severity="HIGH",
                        status="FAILED",
                        resource_id=sg_id,
                        description=f"Default security group '{sg_id}' has rules allowing traffic.",
                        recommendation="Remove all inbound and outbound rules from default security group",
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws ec2 describe-security-groups --group-ids {sg_id} --query 'SecurityGroups[0].{{IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}}'",
                        evidence={"IpPermissions": ingress_rules, "IpPermissionsEgress": egress_rules}
                    )
                    findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.5",
                    title="Unable to Check Default Security Groups",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="security-groups",
                    description=f"Could not verify default security groups: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_security_group_ssh_rdp(self) -> List[Dict[str, Any]]:
        """
        6.3 & 6.4: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server admin ports
        Level: 1 | Type: Automated | CRITICAL
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            security_groups = ec2.describe_security_groups()

            admin_ports = [22, 3389]  # SSH and RDP

            for sg in security_groups.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)
                    ip_ranges = rule.get("IpRanges", [])
                    ipv6_ranges = rule.get("Ipv6Ranges", [])

                    # Check if admin ports are in range
                    for admin_port in admin_ports:
                        if from_port <= admin_port <= to_port:
                            # Check for 0.0.0.0/0
                            for ip_range in ip_ranges:
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    port_name = "SSH" if admin_port == 22 else "RDP"
                                    finding = self.create_finding(
                                        check_id="6.3",
                                        title=f"Security Group Allows {port_name} from Internet",
                                        severity="CRITICAL",
                                        status="FAILED",
                                        resource_id=sg_id,
                                        description=f"Security group '{sg_name}' ({sg_id}) allows {port_name} (port {admin_port}) from 0.0.0.0/0.",
                                        recommendation=f"Restrict {port_name} access to specific IP ranges",
                                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                        command=f"aws ec2 describe-security-groups --group-ids {sg_id} --query 'SecurityGroups[0].IpPermissions[?FromPort<=`{admin_port}` && ToPort>=`{admin_port}`]'",
                                        evidence={"FromPort": from_port, "ToPort": to_port, "CidrIp": "0.0.0.0/0", "Port": admin_port}
                                    )
                                    findings.append(finding)

                            # Check for ::/0
                            for ipv6_range in ipv6_ranges:
                                if ipv6_range.get("CidrIpv6") == "::/0":
                                    port_name = "SSH" if admin_port == 22 else "RDP"
                                    finding = self.create_finding(
                                        check_id="6.4",
                                        title=f"Security Group Allows {port_name} from IPv6 Internet",
                                        severity="CRITICAL",
                                        status="FAILED",
                                        resource_id=sg_id,
                                        description=f"Security group '{sg_name}' ({sg_id}) allows {port_name} (port {admin_port}) from ::/0.",
                                        recommendation=f"Restrict {port_name} access to specific IPv6 ranges",
                                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                        command=f"aws ec2 describe-security-groups --group-ids {sg_id} --query 'SecurityGroups[0].IpPermissions[?FromPort<=`{admin_port}` && ToPort>=`{admin_port}`]'",
                                        evidence={"FromPort": from_port, "ToPort": to_port, "CidrIpv6": "::/0", "Port": admin_port}
                                    )
                                    findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.3",
                    title="Unable to Check Security Group Rules",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="security-groups",
                    description=f"Could not verify security group rules: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_imdsv2_enforcement(self) -> List[Dict[str, Any]]:
        """
        6.7: Ensure that the EC2 Metadata Service only allows IMDSv2
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            instances = ec2.describe_instances()

            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    state = instance.get("State", {}).get("Name", "")
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")

                    if state == "running" and http_tokens != "required":
                        findings.append(
                            self.create_finding(
                                check_id="6.7",
                                title="EC2 Instance Not Enforcing IMDSv2",
                                severity="HIGH",
                                status="FAILED",
                                resource_id=instance_id,
                                description=f"EC2 instance '{instance_id}' does not enforce IMDSv2.",
                                recommendation="Modify instance metadata options to require IMDSv2 (HttpTokens=required)",
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="6.7",
                    title="Unable to Check IMDSv2 Enforcement",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:metadata",
                    description=f"Could not verify IMDSv2 enforcement: {str(e)}",
                    recommendation="Verify EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="6.3",
                title="Security Group Allows SSH from Internet",
                severity="CRITICAL",
                status="FAILED",
                resource_id="sg-0123456789abcdef0",
                description="Security group allows SSH (port 22) from 0.0.0.0/0.",
                recommendation="Restrict SSH access to specific IP ranges",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0 --query 'SecurityGroups[0].IpPermissions[?FromPort<=`22` && ToPort>=`22`]'",
                evidence={"FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0", "Port": 22}
            ),
            self.create_finding(
                check_id="6.5",
                title="Default Security Group Allows Traffic",
                severity="HIGH",
                status="FAILED",
                resource_id="sg-default",
                description="Default security group has rules allowing traffic.",
                recommendation="Remove all rules from default security group",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[0].{IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}'",
                evidence={"IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "IpPermissionsEgress": []}
            ),
            self.create_finding(
                check_id="6.7",
                title="EC2 Instance Not Enforcing IMDSv2",
                severity="HIGH",
                status="FAILED",
                resource_id="i-0123456789abcdef0",
                description="EC2 instance does not enforce IMDSv2.",
                recommendation="Modify instance metadata options to require IMDSv2",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens'",
                evidence={"HttpTokens": "optional", "HttpEndpoint": "enabled"}
            ),
        ]
