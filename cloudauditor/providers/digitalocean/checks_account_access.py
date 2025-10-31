from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class AccountAccessChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        return [
            self.create_finding(
                check_id="do_2.1",
                title="Ensure Secure Sign In for Teams is Enabled (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean:team:secure-sign-in",
                description="Team does not require secure sign-in methods (Google, GitHub, or DO 2FA).",
                recommendation="Enable Secure Sign-In in Team Settings.",
                command="(UI) Control Panel → Settings → Team → Secure sign-in",
                evidence={"secureSignInEnabled": False},
            ),
            self.create_finding(
                check_id="do_2.2",
                title="Ensure Two Factor Authentication for all Accounts/Teams is Enabled (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean:account:2fa",
                description="Two-factor authentication is not enabled for all accounts/teams.",
                recommendation="Enable 2FA for accounts; enforce secure sign-in for team.",
                command="(UI) My Account → Two-factor authentication → Set Up 2FA",
                evidence={"twoFactorEnabled": False},
            ),
            self.create_finding(
                check_id="do_2.3",
                title="Ensure SSH Keys are Audited (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:account:ssh-keys",
                description="SSH keys have not been recently reviewed for appropriateness.",
                recommendation="Audit SSH keys via Settings → Security → SSH Keys and remove stale keys.",
                command="doctl compute ssh-key list --format ID,Name,PublicKey,Created",
                evidence={"keys": [{"id": 123, "name": "old-key", "created": "2021-01-01"}]},
            ),
            self.create_finding(
                check_id="do_2.4",
                title="Ensure a Distribution List is used as the Team Contact Email (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:team:contact-email",
                description="Team contact email is an individual address instead of a distribution list.",
                recommendation="Change Team Contact Email to a distribution list.",
                command="(UI) Control Panel → Settings → Team → Team Contact Email → Edit",
                evidence={"contactEmail": "owner@example.com", "isDistributionList": False},
            ),
        ]


