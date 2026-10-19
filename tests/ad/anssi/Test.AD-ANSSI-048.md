This test looks for managed service accounts whose password has not been renewed for more than 90 days.

Group managed service accounts (gMSA) and standalone managed service accounts (MSA) exist so that nobody has to manage a service password: Windows generates it and replaces it on its own, every 30 days unless another interval was chosen when a gMSA was created. A password that has stayed the same for three months therefore means the automatic renewal is not happening. That can be a configuration problem on the host of the account, and it can also be a sign that someone tampered with the account, so the cause should always be found. A secret that never changes also stays useful to anyone who has obtained it.

#### Remediation action

For each account in the result, find out why its password stopped changing:

- For a standalone MSA, the host it is installed on renews the password. On that host, the "Domain member: Disable machine account password changes" policy should be disabled (registry value `DisablePasswordChange` absent or 0) and "Domain member: Maximum machine account password age" should keep its default of 30 days (`MaximumPasswordAge`), as ANSSI recommends. Check that no GPO overrides them.
- For a gMSA, check its rotation interval (`msDS-ManagedPasswordInterval`). The interval can only be set when the account is created; a gMSA that needs a shorter interval has to be recreated.
- Remove accounts that are no longer used.

If no harmless cause turns up, treat the account as possibly compromised.

#### How the test works

Managed service accounts are objects of the computer class, so the test reads them from the collected computers and recognizes them by their object class, `msDS-GroupManagedServiceAccount` or `msDS-ManagedServiceAccount`. It reports every enabled one whose password was last set more than 90 days ago, or that has no password date at all.

Disabled accounts are ignored. Delegated managed service accounts (dMSA, Windows Server 2025) derive their secret from the machine account and are not evaluated. A gMSA created with an interval longer than 90 days is reported even though it follows its own setting. The test does not read the host settings or the rotation interval; it only looks at the password date. It is skipped when the computers, or their object classes, are not in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Managed service accounts with passwords unchanged for more than 90 days](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_msa_no_change_90)
- [Microsoft: Service accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-service-accounts)
- [Microsoft: ms-DS-ManagedPasswordInterval attribute](https://learn.microsoft.com/windows/win32/adschema/a-msds-managedpasswordinterval)
- [Microsoft: How to disable automatic machine account password changes](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/disable-machine-account-password)

<!--- Results --->

%TestResult%
