This test checks that the Denied RODC Password Replication Group still contains the privileged accounts and groups it is created with.

Every read-only domain controller (RODC) has the Denied RODC Password Replication Group in its never-reveal list, so no RODC will cache the password of anyone in that group. Windows fills it with the groups and accounts whose secrets must never leave the writable domain controllers: Domain Controllers, Read-only Domain Controllers, Group Policy Creator Owners, Domain Admins, Cert Publishers, the krbtgt account and, in the forest root domain, Schema Admins and Enterprise Admins. Removing one of them quietly lets RODCs cache those passwords, which defeats much of the point of having RODCs.

#### Remediation action

Add the missing default members back to the Denied RODC Password Replication Group. Unless there is a strong, documented reason, restore all of them. Then check which accounts already have their password cached on the RODCs, and reset the password of any privileged account found there.

#### How the test works

The test finds the group by its SID (the domain SID followed by 572), reads its direct members over LDAP and resolves them to SIDs with the users and groups that were collected. It fails when the SID of one of the default members of this domain is missing. In the forest root domain, Schema Admins (518) and Enterprise Admins (519) are expected too; in any other domain they belong to the root domain, cannot be resolved from the collected data and are not checked, which the result says.

Only direct members count: a default member that is only present through another group is reported as missing. Extra members are fine. If the members cannot be read, the test is skipped rather than guessing. It is also skipped when the domain SID or the group is not in the collected data.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous configuration of replication groups for RODCs (denied)](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_denied_group)
- [Microsoft: Active Directory security groups, Denied RODC Password Replication](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft: dcpromo, default members of the Denied RODC Password Replication Group](https://learn.microsoft.com/windows-server/administration/windows-commands/dcpromo)

<!--- Results --->

%TestResult%
