This test checks that no domain controller, writable or read-only, runs an operating system for which Microsoft no longer publishes security updates.

Domain controllers hold the secrets of every account in the domain and are the most sensitive systems of an Active Directory. When Microsoft stops publishing security updates for an operating system, any new vulnerability found in it stays exploitable. An attacker who takes over one such domain controller can read or change the whole directory.

#### Remediation action

Migrate the obsolete domain controllers as soon as possible, preferably to the latest version of Windows Server. Add new domain controllers running a supported version, move the Flexible Single Master Operations (FSMO) roles to them, then demote and remove the obsolete ones.

Microsoft sells Extended Security Updates (ESU) for some versions after their end of support. ESU is a paid, time-limited program and a stop-gap for the migration, not a supported state: the test still reports these versions.

#### How the test works

The test finds the computer accounts of the domain controllers: the accounts whose primary group is Domain Controllers or Read-only Domain Controllers, and the accounts referenced by a domain controller entry of the configuration partition. It reads the `operatingSystem` attribute of each account and compares it with a table of Windows versions and their end of extended support, taken from the Microsoft Lifecycle pages. A domain controller fails when the end date of its version is before today.

| Version | Last day of security updates |
| --- | --- |
| Windows 2000 | 2010-07-13 |
| Windows Server 2003 | 2015-07-14 |
| Windows Server 2008 and 2008 R2 | 2020-01-14 |
| Windows Server 2012 and 2012 R2 | 2023-10-10 |
| Windows Server 2016 | 2027-01-12 |
| Windows Server 2019 | 2029-01-09 |
| Windows Server 2022 | 2031-10-14 |
| Windows Server 2025 | 2034-11-14 |

Because the dates are compared with the current date, a version starts failing the day after its end date without any change to the test.

A domain controller whose `operatingSystem` is empty, or is not a Windows version in the table (a Windows Server semi-annual channel release for example), is counted in the result but does not fail the test, because its support status cannot be told from the collected data.

Only the domain controllers of the domain that was collected are evaluated. The test is skipped when no domain controller computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Domain controllers with an obsolete operating system](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dc_obsolete)
- [Microsoft Lifecycle: Windows Server](https://learn.microsoft.com/lifecycle/products/)
- [Microsoft Lifecycle: Windows Server 2016](https://learn.microsoft.com/lifecycle/products/windows-server-2016)

<!--- Results --->

%TestResult%
