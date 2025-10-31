# CloudAuditor Compliance Report

**Generated:** 2025-10-30T02:26:53.514700
**Provider:** DIGITALOCEAN
**Command:** `cloudauditor scan digitalocean --profile test-team --output markdown --output-file test_do_foundations.md`

## Benchmarks Executed
- CIS DigitalOcean Foundations Benchmark v1.0.0

## Summary
- **Total Checks:** 0
- **Passed:** 0
- **Failed:** 3
- **Warnings:** 6

## Findings

### 1. Ensure Secure Sign In for Teams is Enabled (Manual)
- **Check ID:** `do_2.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:team:secure-sign-in`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team does not require secure sign-in methods (Google, GitHub, or DO 2FA).

**Recommendation (CIS):** Enable Secure Sign-In in Team Settings.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Secure sign-in
```

**Evidence/Output:**

```
{'secureSignInEnabled': False}
```

---

### 2. Ensure Two Factor Authentication for all Accounts/Teams is Enabled (Manual)
- **Check ID:** `do_2.2`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:account:2fa`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Two-factor authentication is not enabled for all accounts/teams.

**Recommendation (CIS):** Enable 2FA for accounts; enforce secure sign-in for team.

**Command Executed:**

```
(UI) My Account → Two-factor authentication → Set Up 2FA
```

**Evidence/Output:**

```
{'twoFactorEnabled': False}
```

---

### 3. Ensure SSH Keys are Audited (Automated)
- **Check ID:** `do_2.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:account:ssh-keys`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** SSH keys have not been recently reviewed for appropriateness.

**Recommendation (CIS):** Audit SSH keys via Settings → Security → SSH Keys and remove stale keys.

**Command Executed:**

```
doctl compute ssh-key list --format ID,Name,PublicKey,Created
```

**Evidence/Output:**

```
{'keys': [{'id': 123, 'name': 'old-key', 'created': '2021-01-01'}]}
```

---

### 4. Ensure a Distribution List is used as the Team Contact Email (Manual)
- **Check ID:** `do_2.4`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:team:contact-email`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team contact email is an individual address instead of a distribution list.

**Recommendation (CIS):** Change Team Contact Email to a distribution list.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Team Contact Email → Edit
```

**Evidence/Output:**

```
{'contactEmail': 'owner@example.com', 'isDistributionList': False}
```

---

### 5. Ensure Legacy Tokens are Replaced with Scoped Tokens (Manual)
- **Check ID:** `do_3.1`
- **Severity:** HIGH
- **Status:** FAILED
- **Resource:** `digitalocean:api:legacy-tokens`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Legacy tokens detected without fine-grained scopes.

**Recommendation (CIS):** Replace legacy tokens with custom scoped tokens and retire legacy tokens.

**Command Executed:**

```
doctl auth list; curl -H 'Authorization: Bearer $DIGITALOCEAN_TOKEN' https://api.digitalocean.com/v2/tokens
```

**Evidence/Output:**

```
{'legacyTokens': [{'name': 'legacy-rw', 'created_at': '2022-01-01'}]}
```

---

### 6. Ensure Access Tokens Do Not Have Over-Provisioned Scopes (Manual)
- **Check ID:** `do_3.2`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:api:overprovisioned-scopes`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** One or more tokens have broader scopes than required.

**Recommendation (CIS):** Review and regenerate tokens with least-privilege scopes.

**Command Executed:**

```
(UI) Control Panel → API → Tokens → Scopes
```

**Evidence/Output:**

```
{'tokens': [{'name': 'ci-token', 'scopes': ['*:']}]}
```

---

### 7. Ensure OAuth and Authorized Third-Party Applications are Appropriate (Automated)
- **Check ID:** `do_3.3`
- **Severity:** MEDIUM
- **Status:** WARNING
- **Resource:** `digitalocean:api:oauth-apps`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Authorized third-party applications require review for appropriateness and scope.

**Recommendation (CIS):** Remove unused or unrecognized OAuth/Authorized applications and limit scopes.

**Command Executed:**

```
(UI) Control Panel → API → OAuth Applications / Authorized Applications
```

**Evidence/Output:**

```
{'authorizedApps': [{'name': 'old-ci-app', 'lastUsed': '2023-01-01'}]}
```

---

### 8. Ensure Role-Based Access Controls are Implemented (Manual)
- **Check ID:** `do_4.1`
- **Severity:** HIGH
- **Status:** WARNING
- **Resource:** `digitalocean:team:rbac`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Team roles require review to enforce least privilege.

**Recommendation (CIS):** Use predefined roles (Owner, Member, Biller, Modifier, Billing viewer, Resource viewer) and review assignments.

**Command Executed:**

```
(UI) Control Panel → Settings → Team → Team Members
```

**Evidence/Output:**

```
{'members': [{'email': 'dev@example.com', 'role': 'Owner'}]}
```

---

### 9. Ensure Security History is Reviewed Regularly (Manual)
- **Check ID:** `do_5.1`
- **Severity:** LOW
- **Status:** WARNING
- **Resource:** `digitalocean:team:security-history`
- **Region:** global
- **Compliance:** CIS DigitalOcean Foundations Benchmark v1.0.0

**Description:** Security history review cadence is not documented or recent reviews are missing.

**Recommendation (CIS):** Review Security History regularly and document cadence.

**Command Executed:**

```
(UI) Control Panel → Settings → Security
```

**Evidence/Output:**

```
{'lastReview': None}
```

---