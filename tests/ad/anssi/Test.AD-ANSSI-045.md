This test checks that the password of the krbtgt account has been changed within the last year.

The krbtgt account is the Kerberos infrastructure account of the domain. Its key is used by every domain controller, as a key distribution center, to encrypt and sign the Ticket Granting Tickets (TGTs) it issues. Unlike other accounts, the krbtgt account does not change its password automatically.

An attacker who takes over the krbtgt account can forge TGTs, known as golden tickets, and then authenticate to any resource of the domain (server, workstation and so on) with full administrative privileges, in a more or less stealthy way. The krbtgt secrets can also be extracted from a copy of the account database, for instance one taken by a former administrator, during an audit or for a password strength assessment. A malicious user can then compromise all Active Directory services many years after the copy was made, for as long as the password has not been changed.

#### Remediation action

Change the krbtgt password manually and periodically, so that the Kerberos keys used to encrypt TGTs are renewed.

The change must be carried out twice in a row to effectively prevent the use of previous passwords, because the current and the previous password are both valid at any time. Only do it in an environment where domain controller replication works and is healthy, and leave enough time between the two changes for the new value to replicate to all domain controllers. If the Microsoft script is not used, wait 24 hours between the two changes.

ANSSI recommends the script provided by Microsoft, New-KrbtgtKeys.ps1. Its repository has since been archived. An alternative strategy is to change the password once every 6 months, which revokes all previous passwords every year.

#### How the test works

The test reads the user accounts of the domain and finds the account whose SID ends with the relative identifier 502, which is the krbtgt account even when it has been renamed. It fails when the `pwdLastSet` of that account is more than one year old, or when the password was never set.

Only the krbtgt account of the domain is evaluated. The accounts of read-only domain controllers (`krbtgt_<number>`) are not.

When no account with this relative identifier is in the collected data, the test is skipped because the age of the password is unknown.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Krbtgt account password unchanged for more than a year](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_krbtgt)
- [Microsoft New-KrbtgtKeys.ps1 (archived repository)](https://github.com/microsoftarchive/New-KrbtgtKeys.ps1)

<!--- Results --->

%TestResult%
