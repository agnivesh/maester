This test looks for accounts that are allowed to delegate to a domain controller with protocol transition.

With protocol transition ("Trust this account for delegation to specified services only, use any authentication protocol"), an account does not even need a user to authenticate to it first: it can obtain a ticket in the name of any user it chooses, then use constrained delegation to reach the services listed in its `msDS-AllowedToDelegateTo` attribute. When one of those services runs on a domain controller, or is the krbtgt service, controlling that account is enough to act as a domain administrator on the domain controller and take over the forest.

#### Remediation action

Remove every service principal name that points to a domain controller, or to krbtgt, from the `msDS-AllowedToDelegateTo` attribute of the accounts in the result, from the **Delegation** tab of the account in Active Directory Users and Computers. For managed service accounts, edit the attribute directly or with `Set-ADServiceAccount -Remove`. Also consider whether the account needs protocol transition at all; if not, switch it to Kerberos only.

#### How the test works

The test takes the enabled user and computer accounts that have the TRUSTED_TO_AUTH_FOR_DELEGATION flag, reads the services in their `msDS-AllowedToDelegateTo` attribute and reports those whose host part is the DNS name or short name of a domain controller of the domain, writable or read-only, and those of the krbtgt service. Accounts without protocol transition are reported by ANSSI-AD-008 instead.

Only domain controllers and krbtgt count as privileged here; other sensitive servers are not recognized. Disabled accounts are ignored. The test is skipped when no domain controller computer account is found, or when the delegation targets were not collected.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Constrained delegation with protocol transition to a privileged service](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_delegation_t2a4d)
- [Microsoft: Kerberos constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Configuring Kerberos delegation for group Managed Service Accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts)

<!--- Results --->

%TestResult%
