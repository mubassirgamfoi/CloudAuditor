from typing import Dict, List, Any, Optional
import json
from datetime import datetime

class BaseAzureChecker:
    """
    Base class for Azure security checkers.
    Implements CIS Microsoft Azure Foundations Benchmark v5.0.0
    """

    def __init__(self, subscription_id: str, tenant_id: str, use_mock: bool = True, 
                 credentials_path: Optional[str] = None, cli_command: str = ""):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.use_mock = use_mock
        self.credentials_path = credentials_path
        self.cli_command = cli_command
        self.compliance_standard = "CIS Microsoft Azure Foundations Benchmark v5.0.0"
        
        # Initialize Azure clients if not using mock
        if not self.use_mock and credentials_path:
            self._initialize_clients()

    def _initialize_clients(self):
        """Initialize Azure SDK clients"""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.security import SecurityCenter
            from azure.mgmt.monitor import MonitorManagementClient
            from azure.mgmt.sql import SqlManagementClient
            from azure.mgmt.datalake.store import DataLakeStoreAccountManagementClient
            from azure.mgmt.databricks import DatabricksManagementClient
            
            # Initialize credential
            self.credential = DefaultAzureCredential()
            
            # Initialize clients
            self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
            self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
            self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
            self.keyvault_client = KeyVaultManagementClient(self.credential, self.subscription_id)
            self.security_client = SecurityCenter(self.credential, self.subscription_id)
            self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
            self.sql_client = SqlManagementClient(self.credential, self.subscription_id)
            self.datalake_client = DataLakeStoreAccountManagementClient(self.credential, self.subscription_id)
            self.databricks_client = DatabricksManagementClient(self.credential, self.subscription_id)
            
        except ImportError as e:
            print(f"Warning: Azure SDK not installed. Using mock data. Error: {e}")
            self.use_mock = True

    def create_finding(self, check_id: str, title: str, severity: str, status: str, 
                      resource_id: str, description: str, recommendation: str,
                      command: str = "", evidence: Dict[str, Any] = None, 
                      compliance_standard: str = None) -> Dict[str, Any]:
        """
        Create a standardized finding
        """
        finding = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "region": "global",  # Azure resources are typically global
            "description": description,
            "recommendation": recommendation,
            "compliance_standard": compliance_standard or self.compliance_standard,
            "timestamp": datetime.utcnow().isoformat(),
            "command_executed": command,
            "evidence": evidence or {}
        }
        # Backfill command for automated checks if empty
        if (not command) and ("(automated)" in (title or "").lower()):
            finding["command_executed"] = "az <resource> show/list --output json"
        
        return finding

    def add_command_evidence(self, command: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add command and evidence to a finding
        """
        return {
            "command": command,
            "evidence": evidence
        }

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all checks for this service
        Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement run_checks method")

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for testing
        Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement _get_mock_findings method")
