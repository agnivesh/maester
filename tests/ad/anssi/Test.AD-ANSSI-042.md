This test checks that the Guest account is disabled.

The Guest account is a built-in account of the domain, identified by the relative identifier 501 (`S-1-5-21-<domain>-501`), even when it has been renamed. When it is enabled, it allows unauthenticated network users to log on as Guest with no password.

These unauthorized users can then access any resource that is accessible to the Guest account over the network. This includes any object or shared folder whose permissions allow access to the Guest account, to the Domain Guests group (`S-1-5-21-<domain>-514`), to the Guests group (`S-1-5-32-546`) or to the Everyone group (`S-1-1-0`). This could lead to the exposure or corruption of data.

#### Remediation action

Disable the Guest account:

```powershell
Disable-ADAccount -Identity <Guest account>
```

#### How the test works

The test reads the user accounts of the domain and finds the account whose SID ends with the relative identifier 501. The test fails when that account is enabled. A renamed Guest account is still found. When no account with this relative identifier is in the collected data, the test is skipped because the state of the Guest account is unknown.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Guest account enabled](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_guest)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)

<!--- Results --->

%TestResult%
