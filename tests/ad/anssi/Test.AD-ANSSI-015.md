This test checks that no enabled privileged account has a password set to never expire.

Privileged accounts are the ones that can take over the domain, so their passwords are worth the most to an attacker. When "Password never expires" is set, the domain password policy no longer forces a change. The password can then stay the same for years, and anyone who learned it once, from an old leak, a script or a former colleague, keeps that access.

#### What ANSSI says and how it rates the risk

ANSSI warns that when no mechanism forces a password change, whoever takes over a privileged account keeps access to the domain for a long time. It asks for privileged passwords to be changed at least every three years.

ANSSI rates it level 1. Maester rates it High: a never-expiring password lengthens the time an attacker keeps access, but it does not give the first access.

#### Remediation action

Clear the flag on each account listed in the results, then change its password right away:

```powershell
Set-ADAccountControl -Identity <account> -PasswordNeverExpires $false
```

Passwords do not need to change often: a change every few years is enough when the password is long and strong. If some privileged accounts need a different lifetime from everyone else, give them their own fine-grained password policy (Password Settings Object) instead of turning expiry off.

If the flag is there because the account is really a service account whose password is hard to change, take it out of the privileged groups and give it only the rights it needs. A group managed service account (gMSA) is a better home for such a service, because the domain rotates its password on its own.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each enabled privileged user account that has `DONT_EXPIRE_PASSWORD` (`0x10000`) set in `userAccountControl`. The results list those accounts with the oldest password first and say which protected groups each one reaches.

Some things are not checked:

- computer accounts, whose passwords are random and changed by the computer itself;
- disabled accounts;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged accounts with never-expiring passwords](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dont_expire_priv)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
