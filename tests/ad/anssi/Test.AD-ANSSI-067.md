This test checks that the Allowed RODC Password Replication Group has no members.

Every read-only domain controller (RODC) lists the Allowed RODC Password Replication Group in its password replication policy by default, as the one group whose passwords it may cache. The group itself is created empty. Anyone added to it can therefore have their password stored on every RODC of the domain, including RODCs in places that have nothing to do with that person, which widens what a single stolen RODC gives away.

#### Remediation action

Empty the Allowed RODC Password Replication Group. For each RODC that needs to cache passwords, create a dedicated group that holds only the users and computers of its site, and add that group to the allowed list of that RODC only (`Add-ADDomainControllerPasswordReplicationPolicy -AllowedList`).

Then check which accounts already have their password cached on the RODCs, and reset the passwords of accounts that should not have been there.

#### How the test works

The test finds the group by its SID (the domain SID followed by 571) and reads its direct members over LDAP. It fails when the group has at least one member and lists them with their SID when they are in the collected data. A member that is only nested through another group still counts as one member: the nested group itself is listed.

If the members cannot be read, the test is skipped rather than reporting an empty group. It is also skipped when the domain SID or the group is not in the collected data. The test does not read which passwords are already cached.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous configuration of replication groups for RODCs (allow)](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_allowed_group)
- [Microsoft: Active Directory security groups, Allowed RODC Password Replication](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft: Add-ADDomainControllerPasswordReplicationPolicy](https://learn.microsoft.com/powershell/module/activedirectory/add-addomaincontrollerpasswordreplicationpolicy)

<!--- Results --->

%TestResult%
