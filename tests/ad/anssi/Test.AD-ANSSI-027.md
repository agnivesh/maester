This test checks that only privileged principals can control the roots of the Active Directory naming contexts.

The directory is split into naming contexts: the domain itself (users, groups, computers), Configuration (forest settings and sites), Schema (the definition of every object and attribute), and the two DNS application partitions, DomainDnsZones and ForestDnsZones. Rights on the root of one of them are rights over everything below it that inherits them. The most dangerous one on the domain root is the right to replicate secret data ("Replicating Directory Changes All"), which lets an account ask a domain controller for the password hash of any user, the attack known as DCSync. Full control, changing the permissions or the owner of a root, or writing its attributes give a direct path to the forest as well.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a root, or holds full control, the right to change its permissions or owner, to write all its attributes, all extended rights, the right to replicate secret data, to link group policies, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as creating child objects or writing the manager | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Remove the entries listed in the results from the roots, for example with ADSI Edit or `dsacls`, to bring them back to their default permissions. Rights held by Exchange groups such as Exchange Windows Permissions or Exchange Trusted Subsystem come from Exchange's shared permissions model: install the current Exchange update, run its Active Directory preparation again, and see the section below on switching to split permissions. The Microsoft Entra Connect account needs the right to replicate secret data on the domain root for password hash synchronization, so it is reported when that feature is used: keep the right on that dedicated account only, restrict the account's own permissions as Microsoft documents (`Set-ADSyncRestrictedPermissions`), and protect the account and its server like a domain controller. Any other principal that needs such rights must be made privileged and protected.

#### How the test works

The test reads the RootDSE of the domain controller to find the roots of the domain, Configuration and Schema naming contexts, and of the DomainDnsZones and ForestDnsZones partitions when the controller lists them. It works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups), the groups walked to find them, and a few system principals Windows trusts by default, such as Local System, Enterprise Domain Controllers, Principal Self and Key Admins.

It then reads the owner and the permissions of each root and looks at each entry that applies to the root itself. An allow entry for a principal outside the privileged set is reported when it grants a right from a fixed list, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes the right away. An owner outside the privileged set is reported too. ANSSI does not publish its own list of rights, so the list is Maester's reading of its two levels. The right to replicate ordinary directory changes, without secrets, is not reported.

Some things are not checked:

- entries meant only for objects below a root; they are reported by the tests that look at those objects, when there is one;
- application partitions other than the two DNS ones;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

These objects belong to the whole forest. The test takes the SID of the forest root domain from the domain itself, or, in a child domain, from the trust to the parent domain, and trusts that domain's Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins groups, as it does for the domain it runs in, so that running it from a child domain does not report the default permissions of the forest root. The Domain Admins group of the domain the test runs in stays trusted as well, so a right held by it on these objects is not reported. If the SID of the forest root domain cannot be found, for example in a grandchild domain, which has no trust to the root, the test is skipped.

If a read fails, or the permissions of a root cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no naming context root is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose a naming context root](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_naming_context)
- [Microsoft Learn: Microsoft Entra Connect, configure AD DS Connector account permissions](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-configure-ad-ds-connector-account)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
