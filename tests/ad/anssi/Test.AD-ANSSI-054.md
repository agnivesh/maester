This test checks that every domain controller replicates the SYSVOL share with the Distributed File System Replication (DFSR) service and not with the obsolete File Replication Service (NTFRS).

The NTFRS protocol is obsolete and exposes unnecessary additional administration interfaces on the domain controllers. Recent Windows Server versions have dropped support for NTFRS altogether, which blocks the upgrade of an infrastructure that has not migrated to DFSR: a Windows Server 2019 or later server cannot be promoted in a domain that still replicates SYSVOL with NTFRS.

#### Remediation action

Use DFSR to replicate shares, including SYSVOL. Migrate SYSVOL replication from NTFRS to DFSR with the `dfsrmig` tool, from the Start state through the Prepared and Redirected states to the Eliminated state. The elimination cannot be rolled back, so complete the previous states and check them with `dfsrmig /getmigrationstate` first.

A domain controller listed in the result without a subscription can also have a broken DFSR configuration in a domain that was already migrated. Check its DFSR event log and the `dfsrmig /getmigrationstate` output.

#### How the test works

A domain controller that replicates SYSVOL with DFSR has a subscription object, `CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings`, below its computer account. The test finds the computer accounts of the domain controllers, writable and read-only, and fails when at least one of them has no such object.

The test sees which subscriptions exist, not the migration state of the domain. While the migration is in the Prepared or Redirected state, the subscriptions exist although NTFRS still replicates SYSVOL, so the test can pass before the migration reaches the Eliminated state. A domain controller without a subscription is certainly not replicating SYSVOL with DFSR.

Only the domain controllers of the domain that was collected are evaluated. The test is skipped when no domain controller computer account is in the collected data, or when the DFS Replication subscriptions were not collected.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: SYSVOL replication through NTFRS](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_sysvol_ntfrs)
- [Microsoft: Migrate SYSVOL replication from FRS to DFS Replication](https://learn.microsoft.com/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr)
- [Microsoft: dfsrmig](https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig)
- [Microsoft: SYSVOL DFSR migration fails after you in-place upgrade a domain controller to Windows Server 2019](https://learn.microsoft.com/troubleshoot/windows-server/networking/sysvol-dfsr-migration-fails-after-in-place-upgrade)

<!--- Results --->

%TestResult%
