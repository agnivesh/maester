This test checks that only privileged principals can control the DFS Replication (DFSR) objects that replicate the SYSVOL share.

SYSVOL holds the group policy files and logon scripts that every domain controller serves to every computer of the domain. Since Windows Server 2008 it is replicated by DFSR, which takes its configuration from objects in Active Directory: the "Domain System Volume" replication group below `CN=System` (with its topology, its members and its content set) and, below each domain controller account, the local DFSR settings that subscribe that controller to the group. A principal that can change these objects can register a member of its own or point a subscription elsewhere, push files of its choice into SYSVOL, and have them replicated everywhere. From there, any GPO or script that uses those files runs its code across the domain.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a DFSR object of SYSVOL, or holds full control, the right to change its permissions or owner, to write all its attributes, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as creating child objects (for example a new replication member) or writing the manager | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Bring the objects listed in the results back to their default permissions, for example with ADSI Edit or `dsacls`. Editing these permissions is not needed for normal operation. If a principal really needs rights on them, treat it as an administrator: make it a member of a group protected by AdminSDHolder.

#### How the test works

The test looks for the DFSR replication group named Domain System Volume below `CN=System` of the domain and reads every object below it. It then finds the domain controller accounts, writable and read-only, and reads the DFSR local settings, subscriber and subscription objects below each of them. A domain that does not replicate SYSVOL with DFSR has none of these objects and passes; the SYSVOL replication test reports that case.

It works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups, which includes the domain controller accounts), the groups walked to find them, and a few system principals Windows trusts by default. It reports each right from a fixed list held by a principal outside that set on any of the objects, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. Objects are shown by their distinguished name.

Some things are not checked:

- the permissions of the SYSVOL folders and files on the domain controllers;
- the global DFSR settings container itself and replication groups other than SYSVOL;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of an object cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no SYSVOL DFSR object is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose DFSR settings objects of the SYSVOL share](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_dfsr_sysvol)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
