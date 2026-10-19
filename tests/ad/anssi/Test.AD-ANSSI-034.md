This test checks that no enabled privileged user account has a service principal name (SPN).

An SPN tells Kerberos which account runs a service. Any domain user can ask for a ticket to any SPN, and part of that ticket is encrypted with a key derived from the service account's password. That part can be attacked offline for as long as needed ("Kerberoasting"). A password chosen by a person rarely holds up for long, and on a privileged account the reward for cracking it is the whole domain.

#### Remediation action

For each account listed in the results, pick one of these:

- if the account runs a service, move the service to a group managed service account (gMSA): its password is long, random and changed by the domain on its own;
- if the account needs its privileges but not the service, remove the SPN and change the password;
- if the service needs the account but not its privileges, take the account out of the protected groups and grant only the rights the service needs.

```powershell
Set-ADUser -Identity <account> -ServicePrincipalNames @{ Remove = '<spn>' }
```

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each enabled privileged user account that has at least one SPN. The results list those accounts with the oldest password first, with their SPNs and the protected groups they reach.

Some things are not checked:

- managed service accounts (sMSA, gMSA) and other computer accounts, whose passwords are random;
- the exception ANSSI accepts for accounts covered by a strict fine-grained password policy (long passwords, regular changes, AES only). Such accounts are still reported;
- disabled accounts;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged accounts with SPN](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_spn_priv)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Group Managed Service Accounts overview](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)

<!--- Results --->

%TestResult%
