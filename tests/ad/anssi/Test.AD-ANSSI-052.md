This test checks that no privileged account has its password secrets cached on a read-only domain controller (RODC).

An RODC only keeps the passwords of the accounts its replication policy allows, so that a stolen or compromised branch-office server gives away as little as possible. RODCs usually sit in less protected places than the main domain controllers. If the secrets of an administrator are cached on one, whoever takes over that RODC can sign in as that administrator, and from there take over the whole domain. By default the password replication policy never lets privileged groups be cached; a privileged account on the list means that policy was loosened at some point.

#### Remediation action

For each account listed in the results:

1. change its password right away, since the cached copy may already have been taken (for the krbtgt account, follow the documented krbtgt reset procedure);
2. make sure the RODC's never-reveal list holds the privileged groups again (Administrators, Domain Admins, Account Operators, Server Operators, Backup Operators and Denied RODC Password Replication Group), and that the reveal list does not name the account or a group it belongs to.

```powershell
Get-ADDomainControllerPasswordReplicationPolicy -Identity <rodc> -Denied
Get-ADDomainControllerPasswordReplicationPolicy -Identity <rodc> -Allowed
```

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then finds the RODCs (computer accounts whose primary group is Read-only Domain Controllers) and reads the `msDS-RevealedUsers` attribute of each one, which lists the accounts whose secrets that RODC has received. The attribute is read in pages, so an RODC with thousands of cached accounts is read in full. The test fails for each privileged account found there, user or computer, enabled or disabled. The results list each account with the RODC and the date of its last password change. A domain without an RODC passes.

Some things are not checked:

- whether the password has changed since it was cached, which would make the cached copy useless: the results show the password change date so you can judge, but the account is reported either way;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If the list of an RODC cannot be read, the test is skipped rather than passing.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged users revealed on RODC](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_priv_revealed)
- [Microsoft: Active Directory security groups, Denied RODC Password Replication](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft: Get-ADDomainControllerPasswordReplicationPolicy](https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontrollerpasswordreplicationpolicy)
- [Microsoft: RODC replicates passwords when it's granted incorrect permissions](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/rodc-replicates-passwords-grant-incorrect-permissions)

<!--- Results --->

%TestResult%
