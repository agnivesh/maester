This test checks that no read-only domain controller (RODC) is allowed to cache the passwords of built-in, usually privileged, accounts or groups.

The allow side of an RODC's password replication policy is its `msDS-RevealOnDemandGroup` list: the accounts and groups whose passwords the RODC may keep. Accounts and groups with a relative identifier (RID) below 1000 are the ones Windows creates itself, such as Administrator, Domain Admins or the built-in operator groups. If one of them is in the list, its secrets can be copied to a server that is meant to be expendable, and stolen with it.

#### Remediation action

Remove the privileged entries from the allowed list of the password replication policy of each RODC in the result, with the **Password Replication Policy** tab of the RODC account in Active Directory Users and Computers or `Remove-ADDomainControllerPasswordReplicationPolicy -AllowedList`. Allow dedicated groups that hold only the branch users and computers that need to sign in through that RODC.

Then check which accounts already have their password cached on the RODC, and reset the password of any privileged account found there.

#### How the test works

The test finds the computer accounts of the RODCs and resolves each entry of their `msDS-RevealOnDemandGroup` list to a SID with the users, computers and groups that were collected; a built-in identity may also appear as a foreign security principal. It fails when an entry has a RID below 1000. The Allowed RODC Password Replication Group of this domain (RID 571) is the default entry of the list and is accepted; whether it is empty is checked by ANSSI-AD-067.

An entry that points outside the collected data, for example to another domain, cannot be resolved; it is counted in the result but not judged. The test looks only at the entries of the list, not at the members of the groups it names. A domain without an RODC passes. The test is skipped when the domain SID, the computers or their RODC attributes are not in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous configuration of read-only domain controllers (reveal)](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_reveal)
- [Microsoft: dcpromo, default password replication policy of an RODC](https://learn.microsoft.com/windows-server/administration/windows-commands/dcpromo)
- [Microsoft: Active Directory security groups, Allowed RODC Password Replication](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft: RODC replicates passwords when it's granted incorrect permissions](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/rodc-replicates-passwords-grant-incorrect-permissions)

<!--- Results --->

%TestResult%
