This test checks that no SID history holds a well-known SID or a privileged domain SID.

The `sIDHistory` attribute lets an account or a group carry additional security identifiers (SIDs). A domain migration fills it with the SIDs of the migrated accounts and groups, which are ordinary SIDs. A well-known SID, or the SID of a privileged account or group of a domain, has no reason to be there. Such a value gives the account the access rights of the well-known or privileged principal: an attacker can use it to grant themselves illegitimate access rights, for example by adding the SID of the Enterprise Admins group to a standard account.

#### Remediation action

Investigate why each unexpected SID was granted to the account, computer or group listed in the result. Then clear the `sIDHistory` attribute of the affected objects.

Identify the value, then remove it. For a user account, with the Active Directory PowerShell module:

```powershell
Get-ADUser -Identity <account> -Properties SidHistory | Select-Object -ExpandProperty SIDHistory
Set-ADUser -Identity <account> -Remove @{SIDHistory='S-1-5-21-...'}
```

#### How the test works

The test reads the `sIDHistory` attribute of the users, computers and groups of the domain, including the disabled accounts, and reports each value that is:

| Risk | Rule | Examples |
| --- | --- | --- |
| Well-known SID | The SID is not a domain SID of the form `S-1-5-21-a-b-c-rid`. | Everyone `S-1-1-0`, SYSTEM `S-1-5-18`, built-in Administrators `S-1-5-32-544` |
| Privileged domain SID | The SID is a domain SID whose relative identifier (RID) is below 1000. | Administrator 500, krbtgt 502, Domain Admins 512, Schema Admins 518, Enterprise Admins 519 |

Well-known SIDs are the same in every domain and cannot be migrated: `DsAddSidHistory` fails for accounts that have one. The relative identifiers below 1000 belong to the accounts and groups that Windows creates when it creates a domain, which a migration does not copy. The SID of an ordinary account or group, with a relative identifier of 1000 or more, is not reported by this test; ANSSI-AD-071 reports every SID history.

The test cannot tell that an ordinary SID, for example a custom administrators group created in the former domain, is privileged. Only the objects of the domain that was collected are evaluated. The test is skipped when no user, computer or group is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users, computers or groups fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Accounts or groups with unexpected SID history](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_sidhistory_dangerous)
- [Microsoft: Security identifiers, well-known SIDs](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids)
- [Microsoft Defender for Identity: Unsecure SID History attributes](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-sid-history-attributes)
- [Microsoft: Using DsAddSidHistory](https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory)

<!--- Results --->

%TestResult%
