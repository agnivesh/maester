This test checks that privileged accounts are confined by an enforced authentication policy silo.

An authentication policy silo ties a set of accounts to a set of computers: a silo can say that domain administrators may only sign in from the administration workstations and servers that belong to it, and can shorten the lifetime of their Kerberos tickets. If an administrator's password or ticket is stolen from somewhere else, it then cannot be used from an ordinary workstation. A silo only does this when it is enforced; until then it just writes audit events.

#### Remediation action

Create an authentication policy and a silo for the privileged accounts and the computers they should use (domain controllers, privileged access workstations), test it in audit mode, then enforce it. For each account listed in the results:

```powershell
Grant-ADAuthenticationPolicySiloAccess -Identity <silo> -Account <account>
Set-ADAccountAuthenticationPolicySilo -Identity <account> -AuthenticationPolicySilo <silo>
Set-ADAuthenticationPolicySilo -Identity <silo> -Enforce $true
```

An account needs both steps: access granted by the silo, and the silo assigned to the account. Silos need the Windows Server 2012 R2 domain functional level. Roll them out carefully: an enforced silo with the wrong computers in it locks administrators out.

#### How the test works

The test works out which accounts are members of the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups.

For each enabled member, user or computer, it reads the silo assigned to the account (`msDS-AssignedAuthNPolicySilo`), then reads that silo to see whether it is enforced and whether it grants the account access. The test fails for each account that has no silo, whose silo is not enforced, or whose silo does not list it. The results give the silo and the problem for each account.

Some things are not checked:

- the built-in Administrator account, because authentication policies never apply to it;
- domain controller accounts and disabled accounts;
- what the silo's authentication policy actually restricts;
- members that live outside the collected domain. The results say how many there were.

If a read fails, the test is skipped rather than reporting a result.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged group members not in an authentication silo](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_silo_priv)
- [Microsoft Learn: Authentication policies and authentication policy silos](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos)
- [Microsoft Learn: Guidance about how to configure protected accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)
- [Microsoft Learn: Set-ADAccountAuthenticationPolicySilo](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountauthenticationpolicysilo)

<!--- Results --->

%TestResult%
