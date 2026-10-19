This test checks that every enabled server has authenticated itself within the last 90 days.

Servers must authenticate and change their password at least every 30 days. A server that has not authenticated for a long time is out of sync with the domain: its secrets and its state can no longer be trusted. Such a machine can also be a forgotten or abandoned server that nobody patches or monitors, and its computer account remains usable.

#### Remediation action

Out-of-sync servers must be either reinstalled or removed.

When reinstalling an out-of-sync server, take care not to introduce a new OWNER control path that exposes its computer account. To avoid this, use the `djoin` utility to provision the computer account.

#### How the test works

The test treats a computer account as a server when its `operatingSystem` attribute contains `Server`. It leaves out the domain controllers, which ANSSI-AD-020 checks, and the cluster accounts, the accounts with a service principal name that starts with `MSClusterVirtualServer/`. It ignores the disabled accounts. It fails when the `lastLogonTimestamp` attribute of an enabled server is more than 90 days old.

The `lastLogonTimestamp` attribute is replicated with a delay of up to 14 days by default, which the limit of 90 days absorbs. A server that has no `lastLogonTimestamp` is not counted as inactive: the attribute is empty for an account that never logged on, which does not tell how long the server has been inactive.

The test is skipped when no enabled server computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Inactive servers](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_inactive_servers)
- [Microsoft: Djoin](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff793312(v=ws.11))
- [Microsoft: ms-DS-Logon-Time-Sync-Interval attribute, the replication interval of lastLogonTimestamp](https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval)

<!--- Results --->

%TestResult%
