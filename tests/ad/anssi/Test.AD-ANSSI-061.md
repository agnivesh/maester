This test checks that no user or computer account has a modified primary group.

The `primaryGroupID` attribute of an account grants it an implicit membership in a group. The membership through the primary group does not appear in the list of members of the group in some interfaces, and it does not generate the group membership change events that administrators monitor. An attacker can use a modified value to escalate the privileges of an account without triggering the usual auditing of group membership, or to hide the membership of an account in a group.

#### Remediation action

Reset the `primaryGroupID` attribute of the accounts in the result to the default of their type:

- user accounts: 513 (Domain Users) or 514 (Domain Guests);
- computer accounts: 515 (Domain Computers);
- domain controller accounts: 516 (Domain Controllers);
- read-only domain controller (RODC) accounts: 521 (Read-only Domain Controllers).

If the account legitimately needs the access of the group, add it as an explicit member of that group instead. Before the change, find out when and by whom the attribute was modified: an unexplained value can be the trace of a compromise. Accounts whose primary group is a built-in group below 1000 are the most urgent; they are also reported by ANSSI-AD-031.

#### How the test works

The test reads the primary group ID of every user and computer account, enabled or disabled: the hidden membership applies as soon as a disabled account is enabled again. It compares the value with the default of the account type and fails when an account has another value, whatever the group. A computer is a read-only domain controller when its `userAccountControl` has the PARTIAL_SECRETS_ACCOUNT flag, and a writable domain controller when it has SERVER_TRUST_ACCOUNT; any other computer is expected to have 515.

This test reports every modified value, so the accounts found by ANSSI-AD-031 (a modified value below 1000) are found here as well, each test with its own severity.

The test does not check whether the account is also an explicit member of the group, and it does not read the members of the groups. Accounts without a primary group ID in the collected data are not evaluated, and the test is skipped when no account has one.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Accounts with modified PrimaryGroupID](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_primary_group_id_nochange)
- [Microsoft: Primary-Group-ID attribute](https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid)
- [Microsoft Defender for Identity: Accounts with non-default Primary Group ID](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#accounts-with-non-default-primary-group-id)

<!--- Results --->

%TestResult%
