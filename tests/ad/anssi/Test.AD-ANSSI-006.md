This test checks that the computer accounts of the domain controllers have the attributes a domain controller has by default.

A domain controller is recognized by a set of attributes: the account type flags of its computer object, and the server object and NTDS Settings object of the configuration partition. Some deviations come from a manual or software-induced misconfiguration. Others can reveal malicious activity, for example a computer account made to look like, or to behave like, a domain controller.

#### What ANSSI says and how it rates the risk

ANSSI warns that domain controllers whose attributes are inconsistent may be misconfigured by hand or by software, or may reveal malicious activity.

ANSSI rates it level 1. Maester rates it High: it is a strong sign that something is wrong with a domain controller, but it does not give an attacker access by itself.

#### Remediation action

Investigate each domain controller listed in the result, then correct the inconsistency.

Writable domain controllers must have the following setup:

- The `userAccountControl` attribute of their computer object has the `SERVER_TRUST_ACCOUNT` and `TRUSTED_FOR_DELEGATION` flags set.
- An object of type `server` exists in the configuration partition and its `serverReference` attribute contains the distinguished name of the computer account.
- The `server` object has a child NTDS Settings object of type `nTDSDSA`.

Read-only domain controllers (RODC) must have the following setup:

- The `userAccountControl` attribute of their computer object has the `PARTIAL_SECRETS_ACCOUNT`, `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` and `WORKSTATION_TRUST_ACCOUNT` flags set.
- An object of type `server` exists in the configuration partition and its `serverReference` attribute contains the distinguished name of the computer account.
- The `server` object has a child NTDS Settings object of type `nTDSDSARO`.

Some publishers introduce such deviations when they install their products. Riverbed is a known case.

#### How the test works

The test finds the computer accounts of the domain controllers: the accounts whose primary group is Domain Controllers or Read-only Domain Controllers, and the accounts that a domain controller entry of the configuration partition points to through its server reference. It then checks each account:

| Domain controller | Check |
| --- | --- |
| Writable | The `userAccountControl` value has `SERVER_TRUST_ACCOUNT` (0x2000) and `TRUSTED_FOR_DELEGATION` (0x80000). |
| Writable | A domain controller entry, a server object with an NTDS Settings object of class `nTDSDSA`, points to the computer account. |
| Read-only | The `userAccountControl` value has `PARTIAL_SECRETS_ACCOUNT` (0x04000000), `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (0x01000000) and `WORKSTATION_TRUST_ACCOUNT` (0x1000). |
| Read-only | No writable domain controller entry (class `nTDSDSA`) points to the computer account. |

The test fails when at least one check fails. The typical `userAccountControl` value is 532480 (0x82000) for a writable domain controller and 83890176 (0x5001000) for a read-only one. Other bits can differ without failing the test.

What the test does not verify, because the collected data does not hold it:

- The server object and the NTDS Settings object of class `nTDSDSARO` of read-only domain controllers.
- The `msDS-Behavior-Version` attribute of the NTDS Settings object.
- Domain controllers of other domains of the forest, which have no computer account in the collected data.

The test is skipped when no domain controller computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Domain controllers in an inconsistent state](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dc_inconsistent_uac)
- [Microsoft: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft: Active Directory replication error 8453, typical userAccountControl values of domain controllers](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8453)

<!--- Results --->

%TestResult%
