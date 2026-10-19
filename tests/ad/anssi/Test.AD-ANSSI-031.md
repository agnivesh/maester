This test checks that no user or computer account has a primary group below 1000 other than the default of its type.

The `primaryGroupID` attribute of an account grants it an implicit membership in a group. Group IDs below 1000 are the built-in groups of the domain, such as Domain Admins (512), and are usually privileged. The membership through the primary group does not appear in the list of members of the group in some interfaces, and it does not generate the group membership change events that administrators monitor. An attacker can use it to give an account privileges while hiding the membership.

#### What ANSSI says and how it rates the risk

ANSSI notes that a primaryGroupId below 1000 usually means a privileged group, that membership through this attribute does not show in the member list of some tools, and that it can be used to hide membership.

ANSSI rates it level 1. Maester rates it High: it hides privilege, but whoever sets it already holds the rights to change the account.

#### Remediation action

Reset the `primaryGroupID` attribute of the accounts in the result to the default of their type:

- user accounts: 513 (Domain Users) or 514 (Domain Guests);
- computer accounts: 515 (Domain Computers);
- domain controller accounts: 516 (Domain Controllers);
- read-only domain controller (RODC) accounts: 521 (Read-only Domain Controllers).

If the account legitimately needs the privilege of the group, add it as an explicit member of that group instead. Before the change, find out when and by whom the attribute was modified: an unexplained value can be the trace of a compromise.

#### How the test works

The test reads the primary group ID of every user and computer account, enabled or disabled: the hidden membership applies as soon as a disabled account is enabled again. It compares the value with the default of the account type, and fails when an account has another value lower than 1000. A computer is a read-only domain controller when its `userAccountControl` has the PARTIAL_SECRETS_ACCOUNT flag, and a writable domain controller when it has SERVER_TRUST_ACCOUNT; any other computer is expected to have 515.

Values of 1000 and above that differ from the default are not reported here: ANSSI-AD-061 reports every modified primary group, so an account found by this test is also found by that one.

The test does not check whether the account is also an explicit member of the group, and it does not read the members of the groups. Accounts without a primary group ID in the collected data are not evaluated, and the test is skipped when no account has one.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Accounts with PrimaryGroupID lower than 1000](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_primary_group_id_1000)
- [Microsoft: Primary-Group-ID attribute](https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid)
- [Microsoft Defender for Identity: Accounts with non-default Primary Group ID](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#accounts-with-non-default-primary-group-id)
- [Microsoft: Well-known SIDs](https://learn.microsoft.com/windows/win32/secauthz/well-known-sids)

<!--- Results --->

%TestResult%
