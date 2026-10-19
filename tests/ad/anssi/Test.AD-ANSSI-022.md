This test checks that only privileged principals can control the AdminSDHolder object.

AdminSDHolder is a template. About once an hour, a process on the domain controller that holds the PDC emulator role copies its permissions onto every account and group that Active Directory protects: Domain Admins, Enterprise Admins, the built-in Administrator and the other members of the protected groups. Whoever can change AdminSDHolder can therefore give themselves control over all of these accounts, and the change keeps coming back even if someone repairs the accounts one by one. Out of the box only privileged groups can change this object, so any other principal with a dangerous right there is a direct path to the domain.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns the object, or holds full control, the right to change its permissions or owner, to write all its attributes, all extended rights, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as writing a service principal name, an alternate security identity, the public information property set or the manager | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Open the object `CN=AdminSDHolder,CN=System,<domain>` with ADSI Edit (or `dsacls`) and remove the entries listed in the results, returning the object to its default permissions. If a right belongs to a product account:

- for Exchange, install the latest cumulative and security updates, which remove the excessive rights of the Exchange groups;
- for the Microsoft Entra Connect account, set its permissions again with the cmdlets of the ADSyncConfig module, without the `-IncludeAdminSdHolders` switch, which Microsoft does not recommend.

A delegated group that really needs rights here should itself be privileged and protected: put it in one of the protected groups, and keep its own permissions at least as strict as those of AdminSDHolder.

#### How the test works

The test first works out the privileged set. It starts from the groups that Active Directory protects with AdminSDHolder, reads their members over LDAP, follows nested groups and primary groups, and keeps both the accounts and the groups it walked. To these it adds Local System, Enterprise Domain Controllers, Principal Self, Administrators, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins of the domain, and Enterprise Read-only Domain Controllers, Schema Admins, Enterprise Admins and Enterprise Key Admins of any domain, because Windows grants them rights by default.

It then reads the owner and the permissions of AdminSDHolder and looks at each entry that applies to the object itself, judging it as if it were set on the users, computers and groups the template is copied to (so, for example, the right to add oneself to a group counts). An allow entry for a principal outside the privileged set is reported when it grants a right from a fixed list, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes the right away. An owner outside the privileged set is reported too, since an owner can always change the permissions. ANSSI does not publish its own list of rights, so the list is Maester's reading of its two levels.

Some things are not checked:

- whether a member of a reported group is in fact an administrator: the group itself is outside the privileged set, so it is reported;
- deny entries for other groups, which can only make the test report more than needed;
- the audit part of the descriptor (SACL);
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of AdminSDHolder cannot be read, the test is skipped rather than reporting a result.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous permissions on the adminSDHolder object](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_adminsdholder)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Microsoft Entra Connect, configure AD DS Connector account permissions](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-configure-ad-ds-connector-account)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
