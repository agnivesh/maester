This test checks that the user accounts that run services declare support for Kerberos AES encryption.

An account with a service principal name (SPN) can be the target of a Kerberos service ticket request. The `msDS-SupportedEncryptionTypes` attribute tells the domain controllers which algorithms the account supports, and so which one protects the tickets issued to its service. By default the attribute is empty and the domain controllers apply a default that depends on their patch level and configuration; when it resolves to RC4, any authenticated user can request a ticket for the service and try to crack the password of the account offline (Kerberoasting). Microsoft notes that using AES instead of RC4 by default helps protect against this attack.

#### Remediation action

For the accounts in the result, set `msDS-SupportedEncryptionTypes` explicitly. ANSSI recommends 28 (0x1C), which declares RC4, AES128 and AES256, or the equivalent options in the account tab of the Active Directory Users and Computers console: "This account supports Kerberos AES 128-bits encryption" and "This account supports Kerberos AES 256-bits encryption". To also stop issuing RC4 tickets to the account, use 24 (0x18) once its software supports AES.

Reset the password of an account that was created before AES was supported, so that AES keys exist. Upgrade any software that cannot use AES.

#### How the test works

The test takes the enabled user accounts that have at least one service principal name and fails when one of them has no `msDS-SupportedEncryptionTypes` value, a value of 0, or a value without the AES128 (0x8) and AES256 (0x10) bits. The value 36 (0x24, RC4 with AES session keys) therefore fails: it declares no AES ticket encryption. The result lists the accounts with the decoded value.

Computer accounts are not evaluated, because Windows computers set the attribute themselves. Group managed and managed service accounts are objects of the computer class and are not evaluated either. Disabled accounts are ignored.

An unset attribute fails the test even though Microsoft changed the default in November 2022 and plans to make AES the default of the domain controllers: the effective default depends on the patch level and on the `DefaultDomainSupportedEncTypes` registry value of each domain controller, which the test does not read, and ANSSI asks for an explicit value. The test does not check whether the account's keys include AES keys, nor which algorithm the tickets actually use. The test is skipped when the users, or their attribute, are not in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Service accounts supported encryption algorithms](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_kerberos_properties_encryption)
- [Microsoft: Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft: Kerberos protocol registry entries and KDC configuration keys in Windows](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys)
- [Microsoft: KB5021131, How to manage the Kerberos protocol changes related to CVE-2022-37966](https://support.microsoft.com/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)

<!--- Results --->

%TestResult%
