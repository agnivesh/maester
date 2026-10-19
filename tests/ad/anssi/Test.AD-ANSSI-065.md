This test checks that every read-only domain controller (RODC) refuses to cache the passwords of the built-in privileged groups.

An RODC keeps copies of passwords only for the accounts its password replication policy allows, so that a stolen or compromised RODC exposes as few secrets as possible. The deny side of that policy is the `msDS-NeverRevealGroup` list of the RODC. When a privileged group drops out of that list, the passwords of its members can end up cached on a server that is, by design, less trusted than the writable domain controllers.

#### Remediation action

Put the default entries back in the denied list of the password replication policy of each RODC listed in the result: Administrators, Server Operators, Account Operators, Backup Operators and the Denied RODC Password Replication Group. Use the **Password Replication Policy** tab of the RODC computer account in Active Directory Users and Computers, or `Add-ADDomainControllerPasswordReplicationPolicy -DeniedList`. Keep any extra entries you rely on.

Then check which accounts already have their password cached on the RODC, and reset the password of any privileged account found there: fixing the list does not remove secrets that were already copied.

#### How the test works

The test finds the computer accounts of the RODCs, reads their `msDS-NeverRevealGroup` list and resolves each entry to a SID with the users, computers and groups that were collected; a built-in group may also appear as a foreign security principal. It fails when the list of an RODC lacks the SID of one of the five groups above. The Denied RODC Password Replication Group must be the one of this domain (its SID ends in 572).

Only the entries of the list itself count: a group that is merely nested in another listed group is reported as missing. The test does not check what the groups contain (ANSSI-AD-068 checks the Denied RODC Password Replication Group) nor which passwords are already cached. A domain without an RODC passes. The test is skipped when the domain SID, the computers or their RODC attributes are not in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous configuration of read-only domain controllers (neverReveal)](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_never_reveal)
- [Microsoft: dcpromo, default password replication policy of an RODC](https://learn.microsoft.com/windows-server/administration/windows-commands/dcpromo)
- [Microsoft: Get-ADDomainControllerPasswordReplicationPolicy](https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontrollerpasswordreplicationpolicy)
- [Microsoft: Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)

<!--- Results --->

%TestResult%
