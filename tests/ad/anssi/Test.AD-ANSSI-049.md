This test checks that only privileged principals can control the organizational units and containers that hold privileged accounts.

Group policies reach users and computers through the domain, the sites and the organizational units (OUs) above them. Whoever can link a group policy object (GPO) to an OU that holds administrator accounts, or the computers of domain controllers, can make a policy of their choice run on those accounts or computers: a logon script, a scheduled task, a new local administrator. Full control, changing the permissions or the owner of such an OU, or writing its attributes give the same power. The domain root is not part of this test; the naming context root test covers it.

#### Remediation action

Remove the entries listed in the results, for example with ADSI Edit or `dsacls`, or reset the containers to their default permissions. Keep privileged accounts, groups and computers in a dedicated OU tree (a "tier 0" tree) whose permissions are delegated to no one but administrators, and do not mix them with ordinary accounts in OUs managed by help desk or application teams.

#### How the test works

The test works out the privileged accounts as the other ANSSI permission tests do: the members of the groups Active Directory protects with AdminSDHolder, followed through nested groups and primary groups, plus the built-in Administrator and krbtgt accounts. It then takes every OU and container above those accounts, up to but not including the domain root.

It reads the owner and the permissions of each container and reports each right from a fixed list (linking group policies, full control, changing the permissions or the owner, writing all attributes, creating child objects in a plain container, and the like) held by a principal outside the privileged set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. The privileged set also includes the groups walked to find the accounts and a few system principals Windows trusts by default. Every finding counts as High.

Some things are not checked:

- sites, which can also carry group policy links;
- the group policy objects themselves (the test about GPOs applied to privileged accounts looks at them);
- rights that reach the accounts through inheritance; the test about privileged accounts and groups looks at the accounts directly;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of a container cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no container of privileged accounts is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose privileged object containers](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_gpo_container_priv)
- [Microsoft Learn: Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
