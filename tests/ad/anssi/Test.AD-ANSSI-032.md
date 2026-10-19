This test checks that the domain does not have more privileged accounts than its administrators can realistically keep track of.

Every account in a highly privileged group is a way to take over the domain. When there are dozens of them, nobody knows any more why each one is there, who uses it, or whether it is still needed. Accounts of people who left, test accounts and service accounts pile up, and each is one more password that can leak. ANSSI's guidance is to keep these groups small: operator and replication groups empty, Enterprise Admins and Schema Admins empty except during the operations that need them, and no service accounts among the domain administrators.

#### What ANSSI says and how it rates the risk

ANSSI sets the alert threshold at 50 privileged accounts, or three times the number of domains in the forest, and explains that too many privileged accounts make accountability and clean-up of unused accounts difficult.

ANSSI rates it level 1 (or 2). Maester rates it Medium: it is an accountability and exposure problem and not a weakness that can be used directly.

#### Remediation action

Review the accounts listed in the results with their owners:

- remove the accounts that are no longer needed, and disable those that cannot be removed yet;
- for day-to-day tasks, delegate only the rights a role needs (for example creating users in one OU, or resetting passwords) instead of membership in a privileged group, using the delegation features of Active Directory;
- keep Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Enterprise Admins and Schema Admins empty, and add members only for the time an operation needs them;
- move service accounts out of the privileged groups and grant them only what the service needs.

#### How the test works

The test works out which accounts are members of the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups.

It counts each account once, users and computers, enabled or disabled, leaving out the built-in Administrator account and the domain controller accounts as ANSSI does. The limit is 50 accounts, or 3 per domain of the forest when that is higher; the number of domains is read from the forest's partition list. The test fails when the count is above the limit, and then lists the accounts by name.

ANSSI also defines a second, lower level that counts only user accounts. In a single domain that count can never be over the limit when the first one is not, so the test reports one level, the most severe.

Some things are not checked:

- privileged accounts of the other domains of the forest, which are not collected: only the accounts of this domain are counted;
- members that live outside the collected domain. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than reporting a count that may be too low.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Large privileged group member count](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_privileged_members)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Reducing the Active Directory attack surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)

<!--- Results --->

%TestResult%
