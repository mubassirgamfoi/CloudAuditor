from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class APIChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        return [
            self.create_finding(
                check_id="do_3.1",
                title="Ensure Legacy Tokens are Replaced with Scoped Tokens (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean:api:legacy-tokens",
                description="Legacy tokens detected without fine-grained scopes.",
                recommendation="Replace legacy tokens with custom scoped tokens and retire legacy tokens.",
                command="doctl auth list; curl -H 'Authorization: Bearer $DIGITALOCEAN_TOKEN' https://api.digitalocean.com/v2/tokens",
                evidence={"legacyTokens": [{"name": "legacy-rw", "created_at": "2022-01-01"}]},
            ),
            self.create_finding(
                check_id="do_3.2",
                title="Ensure Access Tokens Do Not Have Over-Provisioned Scopes (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:api:overprovisioned-scopes",
                description="One or more tokens have broader scopes than required.",
                recommendation="Review and regenerate tokens with least-privilege scopes.",
                command="(UI) Control Panel → API → Tokens → Scopes",
                evidence={"tokens": [{"name": "ci-token", "scopes": ["*:"]}]},
            ),
            self.create_finding(
                check_id="do_3.3",
                title="Ensure OAuth and Authorized Third-Party Applications are Appropriate (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:api:oauth-apps",
                description="Authorized third-party applications require review for appropriateness and scope.",
                recommendation="Remove unused or unrecognized OAuth/Authorized applications and limit scopes.",
                command="(UI) Control Panel → API → OAuth Applications / Authorized Applications",
                evidence={"authorizedApps": [{"name": "old-ci-app", "lastUsed": "2023-01-01"}]},
            ),
        ]


