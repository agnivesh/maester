This test checks that only privileged principals can control the privileged accounts and the groups that lead to the protected groups.

Whoever can reset the password of a domain administrator, add themselves to a group nested in Domain Admins, change the permissions of such an account, or take ownership of it, can become an administrator. Most privileged accounts and groups get their permissions from the AdminSDHolder template, so a dangerous entry there shows up on all of them, and the AdminSDHolder test reports it too. Others are not protected by AdminSDHolder: accounts that are privileged only through their primary group, such as domain controllers, and groups nested in the protected groups. Their permissions come from where they sit in the directory and from what was delegated on them.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a privileged account or group, or holds full control, the right to change its permissions or owner, to write all its attributes, to reset its password, to change the members of a group, to set up shadow credentials or resource-based delegation, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as writing a service principal name, an alternate security identity, the public information property set or the manager | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Start with the AdminSDHolder test: fixing the template fixes every protected account and group within the hour. For the remaining entries, remove them from the objects listed in the results, for example with ADSI Edit or `dsacls`, and give the objects back to Domain Admins as owner. Check the organizational units that hold privileged accounts and groups for delegations that reach them through inheritance.

#### How the test works

The test works out the privileged set as the other ANSSI permission tests do: it starts from the groups Active Directory protects with AdminSDHolder, reads their members over LDAP, follows nested groups and primary groups, and keeps the accounts and the groups it walked. A few system principals Windows trusts by default, such as Local System, Enterprise Domain Controllers, Principal Self and Key Admins, are trusted as well.

It then reads the owner and the permissions of each privileged account (users and computers, enabled or not) and of each walked group, one LDAP read per object, and reports each right from a fixed list held by a principal outside the privileged set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. ANSSI does not publish its own list of rights, so the list is Maester's reading of its two levels.

Some things are not checked:

- privileged accounts and groups outside the collected domain. The results say how many members were not checked;
- deny entries for other groups, which can only make the test report more than needed;
- the audit part of the descriptors (SACL).

If a read fails, or the permissions of an object cannot be read (the security descriptor readability test lists such accounts), the test is skipped rather than reporting a result. The test is also skipped when no privileged account or group is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose members of privileged groups](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_privileged_members_perm)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
