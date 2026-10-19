This test checks that every enabled privileged user account is a member of the Protected Users group.

Protected Users is a built-in group that makes its members much harder to steal credentials from. Windows stops caching their passwords and NTLM hashes on the computers they sign in to, refuses NTLM, DES and RC4 for them, never delegates their identity, and makes their Kerberos tickets expire after four hours. For an administrator, whose credentials left on a workstation are the classic way into the domain, that cuts off several common attacks at once.

#### Remediation action

Add the privileged user accounts listed in the results to Protected Users, after checking that they can live with its restrictions:

```powershell
Add-ADGroupMember -Identity 'Protected Users' -Members <account>
```

Go one account at a time and test first: the restrictions have no override, so adding every administrator at once can lock them all out. Before adding an account, change its password on a recent domain controller so that it has AES keys, since members can no longer use RC4. Do not add service accounts or computer accounts: Microsoft advises against it, and they gain no protection because their secret is always stored on the host. A privileged service account is better moved to a group managed service account, or out of the privileged groups.

The group only exists once the PDC emulator role has run on Windows Server 2012 R2 or later, and its domain controller protections need the Windows Server 2012 R2 domain functional level.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then reads the members of Protected Users (the domain SID followed by 525) the same way, nested groups and primary group included, and fails for each enabled privileged user account that is not among them. If the group does not exist, every enabled privileged user account is reported. The results list the accounts by name with the protected groups they reach.

Some things are not checked:

- computer accounts, which should not be members;
- disabled accounts;
- whether the accounts can actually use AES, or whether the domain functional level enables the domain controller protections;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged accounts outside of the Protected Users group](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_protected_users)
- [Microsoft Learn: Protected Users security group](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Microsoft Learn: Guidance about how to configure protected accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

<!--- Results --->

%TestResult%
