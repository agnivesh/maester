This test checks that every enabled privileged account asks for Kerberos preauthentication.

With preauthentication, a user has to prove it knows its password before the domain controller hands out a ticket. When an account has "Do not require Kerberos preauthentication" set, anyone on the network can ask for a ticket for it and get back data encrypted with a key derived from its password. That data can be attacked offline, as long as needed, without a single failed logon showing up. On a privileged account, a cracked password means the domain.

#### Remediation action

Clear the setting on each account listed in the results, then change its password, since it may already have been captured:

```powershell
Set-ADAccountControl -Identity <account> -DoesNotRequirePreAuth $false
```

The setting only exists for very old Kerberos clients. If some software still needs it, upgrade the software rather than keep the setting on an account with this much power.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each enabled privileged user account that has `DONT_REQ_PREAUTH` (`0x400000`) set in `userAccountControl`. The results list those accounts with the oldest password first, which are usually the easiest to crack, and say which protected groups each one reaches.

Some things are not checked:

- computer accounts;
- disabled accounts, for which the domain controller hands out no ticket;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Kerberos preauthentication disabled for privileged accounts](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_kerberos_properties_preauth_priv)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
