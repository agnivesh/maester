This test checks that no account other than a domain controller is trusted for unconstrained Kerberos delegation.

Unconstrained delegation lets an account authenticate to any Kerberos service on behalf of any user who has authenticated to that account. The account receives a copy of the ticket-granting ticket of each user that connects to it. An attacker who controls such an account can impersonate those users, including administrators, elevate privileges and compromise the forest. By default, unconstrained delegation is only granted to domain controllers and must not be granted to any other account.

#### Remediation action

For every account listed in the result, remove the `TRUSTED_FOR_DELEGATION` flag from its `userAccountControl` attribute. This can be done with the Delegation tab of the Active Directory Users and Computers console, by selecting `Do not trust this computer for delegation` or `Trust this computer for delegation to specified services only`.

If Kerberos delegation is really required, use constrained delegation, or resource-based constrained delegation, which restricts the services an account can reach.

#### How the test works

The test reads the user and computer accounts and looks for the `TRUSTED_FOR_DELEGATION` flag (0x80000) of the `userAccountControl` attribute. It ignores the disabled accounts, which cannot authenticate. It ignores the computer accounts of the domain controllers, writable or read-only: the accounts whose primary group is Domain Controllers or Read-only Domain Controllers, and the accounts that a domain controller entry of the configuration partition points to through its server reference.

The test fails when at least one other enabled account has the flag. Constrained delegation, the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` flag and resource-based constrained delegation are not unconstrained delegation and are not reported.

Only the accounts of the domain that was collected are evaluated. The test is skipped when no user or computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users, computers or domain controllers fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Unconstrained authentication delegation](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_delegation_t4d)
- [Microsoft Defender for Identity: Unsecure Kerberos delegation](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-kerberos-delegation)
- [Microsoft: Kerberos constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)

<!--- Results --->

%TestResult%
