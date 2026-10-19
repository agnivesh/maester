This test checks that every enabled domain controller, writable or read-only, has changed the password of its computer account within the last 45 days.

By default, domain controllers change their password automatically every 30 days. When the change does not happen, the secret of the domain controller is not renewed, and the domain controller may be out of sync with the directory. The reason must be investigated as it may be indicative of a compromise.

#### What ANSSI says and how it rates the risk

ANSSI states that domain controllers change their password every 30 days by default, so one that has not changed it for more than 45 days has secrets that are not renewed, and the cause must be investigated because it may indicate a compromise.

ANSSI rates it level 1. Maester rates it Low: in practice it is most often a configuration or health fault, and it is not an attack path on its own.

#### Remediation action

First, check the following registry values on the domain controller:

- `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange` must be set to 0 or not exist.
- `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge` must be set to 30.

Reset incorrect values to their default setting, and check that no Group Policy Object overrides them.

If these values are correct, check that the `NETLOGON` service is started, for example with `sc.exe query netlogon`.

Finally, validate that the password of the machine and that of its account in the Active Directory database are synchronized. Run `nltest /SC_VERIFY:<DomainName>`, where `DomainName` is the NetBIOS name of the domain. Both verifications should display `0 0x0 NERR_Success`.

#### How the test works

The test finds the computer accounts of the domain controllers: the accounts whose primary group is Domain Controllers or Read-only Domain Controllers, and the accounts that a domain controller entry of the configuration partition points to through its server reference. It ignores the disabled accounts. It fails when the `pwdLastSet` attribute of an enabled account is more than 45 days old, or when the password was never set.

The default change every 30 days leaves 15 days of margin before the test fails. Only the domain controllers of the domain that was collected are evaluated.

The test is skipped when no enabled domain controller computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Domain controllers with passwords unchanged for more than 45 days](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_dc_no_change)
- [Microsoft: Domain member, maximum machine account password age](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age)

<!--- Results --->

%TestResult%
