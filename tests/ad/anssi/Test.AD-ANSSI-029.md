This test checks that only privileged principals can control the MicrosoftDNS containers.

The MicrosoftDNS containers hold the DNS zones integrated in Active Directory and the settings of the Microsoft DNS service: one below `CN=System` of the domain, and one in each DNS application partition (DomainDnsZones and ForestDnsZones). Principals that can write these settings can make the DNS service, which usually runs on the domain controllers, load and run code. Out of the box DnsAdmins holds such rights, which is why ANSSI asks for that group to stay unused. Full control, changing the permissions or the owner of a container, writing its attributes or creating zones in it are all reported.

#### Remediation action

Remove the entries listed in the results, for example with ADSI Edit or `dsacls`, starting with those of DnsAdmins. To delegate DNS management without DnsAdmins:

- on `CN=MicrosoftDNS,CN=System` of the domain naming context, grant only what the DNS management console needs to the delegated group;
- in the `DC=DomainDnsZones` partition, grant rights on the zones you want to delegate (with inheritance enabled), rather than on the whole `CN=MicrosoftDNS` container.

Then empty DnsAdmins (see the DnsAdmins test).

#### How the test works

The test looks for a container named MicrosoftDNS directly below `CN=System` of the domain and below the roots of the DomainDnsZones and ForestDnsZones partitions that the domain controller lists. When none is visible the test is skipped instead of passing: an account without read access sees no container, and a pass would then say nothing about the domain. It works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups), the groups walked to find them, and a few system principals Windows trusts by default. DnsAdmins is not part of it.

It then reads the owner and the permissions of each container and reports each right from a fixed list (full control, changing the permissions or the owner, writing all attributes, creating child objects, and the like) held by a principal outside the privileged set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. Every finding counts as Critical.

Some things are not checked:

- the permissions on the zones and DNS records themselves;
- the configuration of the DNS servers, such as the `ServerLevelPluginDll` setting, and whether they are up to date;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of a container cannot be read, the test is skipped rather than reporting a result.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose MicrosoftDNS server objects](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_msdns)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
