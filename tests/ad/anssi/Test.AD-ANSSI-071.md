This test checks that no user, computer or group has a SID history.

The `sIDHistory` attribute lets an account or a group carry one or more additional security identifiers (SIDs) in its list of groups. This mechanism is mainly used during migrations from one domain to another, to keep access to the resources of the former domain. It can also be exploited by an attacker to grant themselves illegitimate access rights. Its legitimate use weakens the security of Kerberos trusts, and it makes log monitoring harder: adding a SID history value generates the audit event 4765, and a failed attempt generates 4766.

#### Remediation action

Clear the `sIDHistory` attribute of every account and group listed in the result, as soon as the domain migrations are completed.

Identify the value, then remove it. For a user account, with the Active Directory PowerShell module:

```powershell
Get-ADUser -Identity <account> -Properties SidHistory | Select-Object -ExpandProperty SIDHistory
Set-ADUser -Identity <account> -Remove @{SIDHistory='S-1-5-21-...'}
```

Before removing a value, check that no resource still relies on the former SID in its access control lists, and re-apply the permissions to the new identity where needed.

#### How the test works

The test reads the `sIDHistory` attribute of the users, computers and groups of the domain. It fails when at least one of them has a value. Disabled accounts are included: the attribute is a leftover of a migration whatever the state of the account.

ANSSI-AD-053 reports the objects whose SID history holds a well-known or privileged SID. Those objects fail this test too, at a higher severity there.

Only the objects of the domain that was collected are evaluated. The test is skipped when no user, computer or group is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users, computers or groups fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Accounts or groups with SID history set](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_sidhistory_present)
- [Microsoft Defender for Identity: Unsecure SID History attributes](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-sid-history-attributes)
- [Microsoft: Appendix L, events to monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Microsoft: Using DsAddSidHistory](https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory)

<!--- Results --->

%TestResult%
