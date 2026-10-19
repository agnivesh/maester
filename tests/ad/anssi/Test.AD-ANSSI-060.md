This test checks that every enabled server has changed the password of its computer account within the last 45 days.

By default, servers change their password automatically every 30 days. When the change does not happen, the secret of the server is not renewed. The reason must be investigated as it may be indicative of a compromise.

#### Remediation action

First, check the following registry values on the server:

- `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange` must be set to 0 or not exist.
- `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge` must be set to 30.

Reset incorrect values to their default setting, and check that no Group Policy Object overrides them.

If these values are correct, check that the `NETLOGON` service is started, for example with `sc.exe query netlogon`.

Finally, validate that the password of the machine and that of its account in the Active Directory database are synchronized. Run `nltest /SC_VERIFY:<DomainName>`, where `DomainName` is the NetBIOS name of the domain. Both verifications should display `0 0x0 NERR_Success`.

#### How the test works

The test treats a computer account as a server when its `operatingSystem` attribute contains `Server`. It leaves out the domain controllers, which ANSSI-AD-019 checks, and the cluster accounts, the accounts with a service principal name that starts with `MSClusterVirtualServer/`, which ANSSI-AD-047 checks. It ignores the disabled accounts. It fails when the `pwdLastSet` attribute of an enabled server is more than 45 days old, or when the password was never set.

The default change every 30 days leaves 15 days of margin before the test fails. A server that is switched off or no longer authenticates also fails this test; ANSSI-AD-059 reports those servers separately. A server whose password is older than 90 days also fails ANSSI-AD-046.

The test is skipped when no enabled server computer account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Servers with passwords unchanged for more than 45 days](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_server_no_change_45)
- [Microsoft: Domain member, maximum machine account password age](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age)

<!--- Results --->

%TestResult%
