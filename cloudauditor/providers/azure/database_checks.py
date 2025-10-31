from typing import Dict, List, Any
from cloudauditor.providers.azure.base_checker import BaseAzureChecker

class DatabaseChecker(BaseAzureChecker):
    """
    Checker for Azure Database Services configurations.
    Implements CIS Microsoft Azure Database Services Benchmark v1.0.0
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        findings: List[Dict[str, Any]] = []
        # Real API calls would go here
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        benchmark = "CIS Microsoft Azure Database Services Benchmark v1.0.0"
        return [
            # Cosmos DB
            self.create_finding(
                check_id="azdb_3.1",
                title="Cosmos DB: Use selected networks (not all) (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:cosmosdb:network-selected-networks",
                description="Cosmos DB allows access from all networks.",
                recommendation="Set Public network access to Selected networks and configure VNets.",
                compliance_standard=benchmark,
                command="az cosmosdb show --name <ACCOUNT> --resource-group <RG> --query 'isVirtualNetworkFilterEnabled'",
                evidence={"isVirtualNetworkFilterEnabled": False}
            ),
            self.create_finding(
                check_id="azdb_3.2",
                title="Cosmos DB: Private endpoints are used (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:cosmosdb:private-endpoints",
                description="No private endpoint configured for Cosmos DB.",
                recommendation="Create a Private Endpoint with Approved connection state.",
                compliance_standard=benchmark,
                command="az network private-endpoint-connection list --id $(az cosmosdb show --name <ACCOUNT> --resource-group <RG> --query id -o tsv)",
                evidence={"privateEndpoints": []}
            ),
            # MySQL
            self.create_finding(
                check_id="azdb_6.1",
                title="MySQL: Enforce SSL connection is Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:mysql:enforce-ssl",
                description="MySQL server does not enforce SSL connections.",
                recommendation="Enable Enforce SSL connection on the MySQL server.",
                compliance_standard=benchmark,
                command="az mysql server show --resource-group <RG> --name <SERVER> --query sslEnforcement",
                evidence={"sslEnforcement": "Disabled"}
            ),
            self.create_finding(
                check_id="azdb_6.2",
                title="MySQL Flexible: TLS version set to TLS1.2+ (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:mysql:flexible-tls-version",
                description="MySQL flexible server allows TLS versions lower than 1.2.",
                recommendation="Set server parameter tls_version to TLSV1.2 or higher.",
                compliance_standard=benchmark,
                command="az mysql flexible-server parameter show --name tls_version --resource-group <RG> --server-name <SERVER>",
                evidence={"value": "TLSv1"}
            ),
            self.create_finding(
                check_id="azdb_6.3",
                title="MySQL: audit_log_enabled is ON (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:mysql:audit-log-enabled",
                description="MySQL audit logging is not enabled.",
                recommendation="Set audit_log_enabled ON and configure diagnostic settings.",
                compliance_standard=benchmark,
                command="(Portal) Server parameters -> audit_log_enabled",
                evidence={"audit_log_enabled": "OFF"}
            ),
            # PostgreSQL
            self.create_finding(
                check_id="azdb_7.1",
                title="PostgreSQL: Enforce SSL connection Enabled (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:postgres:enforce-ssl",
                description="PostgreSQL server does not enforce SSL connections.",
                recommendation="Enable Enforce SSL connection.",
                compliance_standard=benchmark,
                command="az postgres server show --resource-group <RG> --name <SERVER> --query sslEnforcement",
                evidence={"sslEnforcement": "Disabled"}
            ),
            self.create_finding(
                check_id="azdb_7.2",
                title="PostgreSQL: log_checkpoints ON (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:postgres:log_checkpoints",
                description="log_checkpoints is not enabled.",
                recommendation="Set log_checkpoints to ON.",
                compliance_standard=benchmark,
                command="az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_checkpoints",
                evidence={"value": "off"}
            ),
            self.create_finding(
                check_id="azdb_7.3",
                title="PostgreSQL: log_connections ON (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:postgres:log_connections",
                description="log_connections is not enabled.",
                recommendation="Set log_connections to ON.",
                compliance_standard=benchmark,
                command="az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_connections",
                evidence={"value": "off"}
            ),
            self.create_finding(
                check_id="azdb_7.4",
                title="PostgreSQL: log_disconnections ON (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:postgres:log_disconnections",
                description="log_disconnections is not enabled.",
                recommendation="Set log_disconnections to ON.",
                compliance_standard=benchmark,
                command="az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_disconnections",
                evidence={"value": "off"}
            ),
            self.create_finding(
                check_id="azdb_7.5",
                title="PostgreSQL: connection_throttling ON (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:postgres:connection_throttling",
                description="connection_throttling is not enabled.",
                recommendation="Set connection_throttling to ON.",
                compliance_standard=benchmark,
                command="az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name connection_throttling",
                evidence={"value": "off"}
            ),
            self.create_finding(
                check_id="azdb_7.6",
                title="PostgreSQL: log_retention_days > 3 (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:postgres:log_retention_days",
                description="log_retention_days set too low.",
                recommendation="Set log_retention_days between 4 and 7 inclusive.",
                compliance_standard=benchmark,
                command="az postgres server configuration show --resource-group <RG> --server-name <SERVER> --name log_retention_days",
                evidence={"value": "3"}
            ),
            self.create_finding(
                check_id="azdb_7.7",
                title="PostgreSQL: 'Allow access to Azure services' disabled (Automated)",
                severity="MEDIUM",
                status="FAILED",
                resource_id="azure:postgres:allow-azure-services",
                description="Firewall rule AllowAllWindowsAzureIps is present.",
                recommendation="Remove AllowAllWindowsAzureIps and define specific firewall/VNet rules.",
                compliance_standard=benchmark,
                command="az postgres server firewall-rule list --resource-group <RG> --server-name <SERVER>",
                evidence={"rules": [{"name": "AllowAllWindowsAzureIps", "startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}]}
            ),
            # SQL Database / SQL Server
            self.create_finding(
                check_id="azdb_10.1",
                title="SQL: Server auditing is On (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:sql:server-auditing",
                description="SQL Server auditing is not enabled.",
                recommendation="Enable auditing to Log Analytics/Event Hub/Storage with retention.",
                compliance_standard=benchmark,
                command="(Portal/PowerShell) Get-AzSqlServerAudit",
                evidence={"auditing": "Disabled"}
            ),
            self.create_finding(
                check_id="azdb_10.2",
                title="SQL: No ingress from 0.0.0.0/0 (Automated)",
                severity="HIGH",
                status="FAILED",
                resource_id="azure:sql:server-firewall-any",
                description="SQL server firewall permits any IP or 'AllowAllWindowsAzureIps'.",
                recommendation="Remove broad rules and configure specific IP ranges only.",
                compliance_standard=benchmark,
                command="az sql server firewall-rule list --resource-group <RG> --server <SERVER>",
                evidence={"rules": [{"name": "AllowAllWindowsAzureIps"}, {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}]}
            ),
            self.create_finding(
                check_id="azdb_10.3",
                title="SQL: TDE protector uses Customer-managed key (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:sql:tde-cmk",
                description="SQL Server TDE protector not configured with CMK in Key Vault.",
                recommendation="Configure server TDE protector with Azure Key Vault CMK.",
                compliance_standard=benchmark,
                command="az sql server tde-key show --resource-group <RG> --server <SERVER>",
                evidence={"serverKeyType": "ServiceManaged"}
            ),
            self.create_finding(
                check_id="azdb_10.4",
                title="SQL: Entra authentication configured (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:sql:entra-admin",
                description="No Entra admin configured for SQL Server.",
                recommendation="Set a Microsoft Entra admin for SQL Server.",
                compliance_standard=benchmark,
                command="az sql server ad-admin list --resource-group <RG> --server <SERVER>",
                evidence={"admins": []}
            ),
            self.create_finding(
                check_id="azdb_10.5",
                title="SQL DB: Data encryption (TDE) is On (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:sqldb:tde-on",
                description="Transparent Data Encryption is not enabled on a database.",
                recommendation="Enable TDE for all user databases.",
                compliance_standard=benchmark,
                command="az sql db tde show --resource-group <RG> --server <SERVER> --database <DB> --query status",
                evidence={"status": "Disabled"}
            ),
            self.create_finding(
                check_id="azdb_10.6",
                title="SQL: Auditing retention > 90 days (Automated)",
                severity="LOW",
                status="WARNING",
                resource_id="azure:sql:auditing-retention",
                description="Auditing retention less than 90 days or disabled.",
                recommendation="Set auditing retention to 90+ days or unlimited.",
                compliance_standard=benchmark,
                command="(PowerShell) Get-AzSqlServerAudit | Select RetentionInDays",
                evidence={"RetentionInDays": 30}
            ),
            self.create_finding(
                check_id="azdb_10.7",
                title="SQL: Public Network Access is Disabled (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="azure:sql:public-network-access",
                description="SQL server public network access is enabled.",
                recommendation="Disable Public network access under Networking.",
                compliance_standard=benchmark,
                command="(Portal) SQL Server -> Networking -> Public access",
                evidence={"publicNetworkAccess": "Enabled"}
            ),
        ]
