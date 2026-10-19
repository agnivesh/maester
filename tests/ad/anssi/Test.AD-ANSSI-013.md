This test checks that the DnsAdmins group is empty and that only privileged principals can control it.

Members of DnsAdmins manage the Microsoft DNS service, which usually runs on the domain controllers. Besides managing every zone of the domain, they can use debugging and undocumented features of the server, including, depending on patches and configuration, loading a plug-in DLL into the DNS service (the `ServerLevelPluginDll` setting) and restarting it. Microsoft fixed one such path (CVE-2021-40469), but the dangerous features can be turned back on, and the state of every DNS server cannot be seen from Active Directory. DnsAdmins is therefore an administrator group in practice, without the protection Active Directory gives to the real ones. A principal that can change its members, its permissions or its owner can make itself a member.

#### Remediation action

Stop using DnsAdmins:

- delegate DNS management with permissions instead: on `CN=MicrosoftDNS,CN=System` in the domain naming context for the management console, and on the `CN=MicrosoftDNS` container of the zones you want to delegate in the `DC=DomainDnsZones` partition;
- remove every member from DnsAdmins;
- make Domain Admins the owner of the group, remove the entries listed in the results, and consider adding a deny entry for Everyone on changing its owner, its permissions and its members.

#### How the test works

The test looks for a group whose account name is DnsAdmins. The group has no fixed security identifier, so a renamed group is not found; a domain without such a group passes. It reads the members of the group over LDAP, follows nested groups, and adds the accounts whose primary group is DnsAdmins. Any member fails the test: user and computer accounts, nested groups (even empty ones) and members outside the collected data, such as principals of another domain.

It then reads the owner and the permissions of the group and reports, as the other ANSSI permission tests do, each right from a fixed list (full control, changing the members, the permissions or the owner, writing all attributes, and the like) held by a principal outside the privileged set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too; ANSSI asks for Domain Admins as the owner, but the test accepts any privileged owner. The privileged set is the groups Active Directory protects with AdminSDHolder, their members, the groups walked to find them, and a few system principals Windows trusts by default.

Some things are not checked:

- the configuration of the DNS servers themselves, such as `ServerLevelPluginDll`, and whether they are up to date;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of the group cannot be read, the test is skipped rather than reporting a result.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous permissions on the DnsAdmins group](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dnsadmins)
- [Microsoft Security Response Center: CVE-2021-40469, Windows DNS Server remote code execution](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40469)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
