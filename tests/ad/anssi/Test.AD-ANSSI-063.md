This test checks that no privileged account keeps its password with reversible encryption.

When "Store password using reversible encryption" is set on an account, the domain keeps a copy of its password that can be turned back into the original text. Anyone who gets hold of the directory database, for example from a domain controller backup or by replicating secrets with enough rights, can read those passwords as they were typed. For a privileged account this hands over the account outright, and the same password may well be in use elsewhere.

#### Remediation action

Clear the setting on each account listed in the results, then change its password, since the readable copy may stay until the password changes.

```powershell
Set-ADAccountControl -Identity <account> -AllowReversiblePasswordEncryption $false
```

A few old protocols (CHAP, IIS Digest authentication) need the setting. If one of them really needs a privileged account, document why, for example in the account description, and look for a way to retire that dependency.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each privileged user account that has `ENCRYPTED_TEXT_PWD_ALLOWED` (`0x80`) set in `userAccountControl`, enabled or not, since the readable password is stored either way. The results list those accounts by name with their state and the protected groups they reach.

Some things are not checked:

- computer accounts;
- the domain-wide "Store passwords using reversible encryption" policy, which has a test of its own;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged accounts with passwords stored using reversible encryption](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_reversible_password_priv_uac)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Policy CSP, Store passwords using reversible encryption](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-devicelock#cleartextpassword)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
