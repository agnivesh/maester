This test checks that every `krbtgt_*` account of the domain belongs to a read-only domain controller (RODC).

Every RODC has its own `krbtgt_` account, whose name ends with a number that identifies the RODC, and uses it to provide cryptographic isolation for the tickets it issues. When an RODC is promoted or demoted, Windows manages the account. If an RODC fails and its metadata is not cleaned up, the account can remain in Active Directory as an orphan. ANSSI reports these leftover accounts: they serve no RODC and can be deleted.

#### Remediation action

Delete the orphan `krbtgt_` accounts, after checking each one. Deleting an account that is still in use stops the Kerberos Key Distribution Center on the RODC it belongs to, which then fails to start and cannot replicate. Before the deletion, check that no computer account points to the `krbtgt_` account through its `msDS-KrbTgtLink` attribute, and that the RODC it was created for no longer exists.

#### How the test works

The test lists the user accounts whose name starts with `krbtgt_` and the `msDS-KrbTgtLink` value of every computer account, and reports the accounts that no computer points to. The built-in `krbtgt` account has no suffix and is not evaluated. A domain without any `krbtgt_` account, which is the usual case when there is no RODC, passes.

The test does not check that the RODC that an account points to is still alive, nor that the account has been used. Every account whose name starts with `krbtgt_` is treated as an RODC account. The test is skipped when the users, or the `msDS-KrbTgtLink` attribute of the computers, are not in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Orphan RODC krbtgt accounts](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_rodc_orphan_krbtgt)
- [Microsoft: ms-DS-KrbTgt-Link attribute](https://learn.microsoft.com/windows/win32/adschema/a-msds-krbtgtlink)
- [Microsoft: KDC service on an RODC can't start and generates error 1450](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kdc-service-on-rodc-cant-start-error-1450)

<!--- Results --->

%TestResult%
