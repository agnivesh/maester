This test checks that every enabled domain controller, writable or read-only, has authenticated itself within the last 45 days.

Domain controllers must authenticate and change their password at least every 30 days. A domain controller that has not authenticated for a long time is out of sync with the domain: it no longer replicates, and its secrets and its state can no longer be trusted. Such a machine can also be a forgotten or abandoned domain controller that nobody patches or monitors.

#### What ANSSI says and how it rates the risk

ANSSI states that domain controllers must authenticate and change their password at least every 30 days. One that has not authenticated for more than 45 days is out of sync and must be reinstalled or removed.

ANSSI rates it level 1. Maester rates it Low: an out-of-sync domain controller is an untidy, unhealthy machine rather than a direct attack path.

#### Remediation action

Out-of-sync domain controllers must be either reinstalled or removed.

When reinstalling an out-of-sync domain controller, take care not to introduce a new OWNER control path that exposes its computer account. To avoid this, use the `djoin` utility to provision the computer account.

#### How the test works

The test finds the computer accounts of the domain controllers: the accounts whose primary group is Domain Controllers or Read-only Domain Controllers, and the accounts that a domain controller entry of the configuration partition points to through its server reference. It ignores the disabled accounts. It fails when the `lastLogonTimestamp` attribute of an enabled account is more than 45 days old.

The `lastLogonTimestamp` attribute is replicated with a delay of up to 14 days by default. The limit of 45 days absorbs this delay and the default change of the password every 30 days. A domain controller that has no `lastLogonTimestamp` is not counted as inactive: the attribute is empty for an account that never logged on, which does not tell how long the controller has been inactive.

Only the domain controllers of the domain that was collected are evaluated.

The test is skipped when no enabled domain controller computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Inactive domain controllers](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_inactive_dc)
- [Microsoft: Djoin](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff793312(v=ws.11))
- [Microsoft: ms-DS-Logon-Time-Sync-Interval attribute, the replication interval of lastLogonTimestamp](https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval)

<!--- Results --->

%TestResult%
