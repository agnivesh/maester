This test checks that the security descriptor of every privileged account can be read.

The security descriptor of an account says who owns it and who may change it. Several other tests depend on it, and so does any review of who can take control of an administrator account. When the account running the scan cannot read the descriptor of a privileged account, those checks silently have nothing to look at for that account. Sometimes this is just a scan run with too few rights. It can also be deliberate: denying read access to an object's permissions is a known way to hide an account, or a backdoor on it, from ordinary inspection.

#### Remediation action

For each account listed in the results, find out why its permissions cannot be read:

- if the scan ran with an account that has too few rights, run it again with an account allowed to read the security descriptors of all objects;
- otherwise look at the permissions of the account and of the organizational units above it for entries that deny reading permissions, and remove them unless there is a documented reason for them.

Privileged accounts normally get their permissions from the AdminSDHolder template every hour, so a deny that keeps coming back points at the AdminSDHolder object itself.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then reads the security descriptor (owner, group and permissions) of each privileged account, users and computers, enabled or disabled, one LDAP read per account. It fails for each account whose descriptor does not come back. The results list those accounts by name with their type and the protected groups they reach.

Some things are not checked:

- whether other attributes of the accounts could be read;
- the audit part of the descriptor (SACL), which needs extra rights to read;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a read fails outright, the test is skipped rather than reporting a result.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Critical information missing for privileged accounts](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_sd_failed_sd_read_on_priv)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

<!--- Results --->

%TestResult%
