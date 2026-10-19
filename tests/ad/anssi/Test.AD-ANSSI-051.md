This test checks that privileged accounts still carry the adminCount marker that Active Directory puts on them.

Every hour, the domain controller holding the PDC emulator role gives the members of protected groups a locked-down set of permissions and sets their `adminCount` attribute to 1. Nothing in normal administration sets it back to 0. A privileged account with `adminCount` cleared was changed by hand, and some tools that hunt for privileged accounts look only at `adminCount`. Clearing it is a cheap way to hide an account from them.

#### Remediation action

Find out who changed `adminCount` on the accounts listed in the results and why, for example from the directory change audit logs. Then set it back:

```powershell
Set-ADUser -Identity <account> -Replace @{ adminCount = 1 }
```

If the account should not be privileged at all, take it out of the protected groups instead.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each privileged user account whose `adminCount` is unset or 0, enabled or not. The results list those accounts by name with their `adminCount` value and the protected groups they reach.

Some things are not checked:

- accounts that are privileged only through their primary group, such as domain controllers: Microsoft does not document whether AdminSDHolder marks them;
- computer accounts, because their `adminCount` is not collected;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

An account that has just been added to a protected group may fail until the next AdminSDHolder run, at most an hour later by default. If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged group members with adminCount null or 0](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_privileged_members_no_admincount)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount)

<!--- Results --->

%TestResult%
