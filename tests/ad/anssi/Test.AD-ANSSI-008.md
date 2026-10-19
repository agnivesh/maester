This test looks for accounts that are allowed to delegate to a domain controller with Kerberos constrained delegation.

Constrained delegation lets a service account act for a user towards the services listed in its `msDS-AllowedToDelegateTo` attribute: once a user authenticates to that account, the account can ask for a ticket to one of those services in the user's name. When a listed service runs on a domain controller, or is the krbtgt service, whoever controls the delegating account can reach the domain controller as any user who authenticates to it, including administrators. That is a direct path to taking over the domain.

#### Remediation action

Remove every service principal name that points to a domain controller, or to krbtgt, from the `msDS-AllowedToDelegateTo` attribute of the accounts in the result, from the **Delegation** tab of the account in Active Directory Users and Computers. For group managed and standalone managed service accounts, which have no such tab, edit the attribute directly or with `Set-ADServiceAccount -Remove`. If a service genuinely needs to reach a domain controller, find another design: delegation to a domain controller should not be allowed.

#### How the test works

The test takes the enabled user and computer accounts, reads the services in their `msDS-AllowedToDelegateTo` attribute and reports those whose host part is the DNS name or short name of a domain controller of the domain, writable or read-only, and those of the krbtgt service. Accounts that also have protocol transition ("use any authentication protocol") are left to ANSSI-AD-010, so each account is reported once.

Only domain controllers and krbtgt count as privileged here. Delegation to other sensitive servers, such as certificate authorities or administration servers, is not recognized. Disabled accounts are ignored. The test is skipped when no domain controller computer account is found, or when the delegation targets were not collected.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Constrained authentication delegation to privileged service](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_delegation_a2d2)
- [Microsoft: Kerberos constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Configuring Kerberos delegation for group Managed Service Accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts)

<!--- Results --->

%TestResult%
