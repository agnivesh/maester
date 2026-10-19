This test checks that only privileged principals can control the computer objects of the domain controllers.

A domain controller's computer object holds the settings that make it a controller and the account it uses to authenticate. Someone who controls the object of a writable controller can, in practice, take over that account and replicate every secret of the domain, the passwords of the domain administrators included. On a read-only domain controller (RODC) the damage is smaller but still serious: the attacker can read the secrets the RODC is allowed to cache and become a local administrator of it. The principal named as the manager of an RODC (its `managedBy` attribute) is a local administrator by design.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a controller object, manages an RODC, or holds full control, the right to change permissions or owner, to write all attributes, to reset the password, to set up resource-based delegation or shadow credentials, to change the manager of an RODC, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as writing a service principal name, an alternate security identity, the public information property set or the manager of a writable controller | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Remove the entries listed in the results from the controller objects, for example with ADSI Edit or `dsacls`, and give the objects back to Domain Admins as owner. An account that really needs rights on domain controllers must be treated as privileged: make it a member of Domain Admins or Enterprise Admins so that AdminSDHolder protects it. For an RODC, name as manager only a group whose members are allowed to administer that RODC, and keep that group as tightly controlled as the controller itself.

#### How the test works

The test finds the computer accounts of all domain controllers, writable and read-only, and works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups), the groups walked to find them, and a few system principals Windows trusts by default, such as Local System, Enterprise Domain Controllers, Principal Self and Key Admins.

It then reads the owner and the permissions of each controller object and looks at each entry that applies to the object itself. An allow entry for a principal outside the privileged set is reported when it grants a right from a fixed list, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes the right away. An owner outside the privileged set is reported too. For each RODC, the manager is reported when it is outside the privileged set (or not in the collected data), and the right to change the manager counts as level 1. ANSSI does not publish its own list of rights, so the list is Maester's reading of its two levels.

Some things are not checked:

- the server and NTDS Settings objects of the controllers in the configuration partition;
- deny entries for other groups, which can only make the test report more than needed;
- the audit part of the descriptor (SACL);
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of a controller object cannot be read, the test is skipped rather than reporting a result.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose domain controller objects](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_dc)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
