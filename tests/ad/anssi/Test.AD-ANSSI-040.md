This test checks that the domain controllers (DCs) and read-only domain controllers (RODCs) only support AES for Kerberos.

Domain controllers can support several algorithms to encrypt Kerberos tickets: DES, RC4 and AES. At first, only RC4 was supported on Windows, and DES could be enabled for compatibility with non-Windows systems. AES128 and AES256 have been supported since Windows Server 2008. Today the DES algorithms (DES-CBC-CRC and DES-CBC-MD5) are obsolete, and in a hardening perspective RC4 should be disabled as well, at the price of losing compatibility with systems older than Windows Vista and Windows Server 2008.

#### Severity levels

In the Maester report the severity of this test is always High, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

The severity depends on the worst condition found on the domain controllers. A controller that breaks several rules is reported once, with its most severe level.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| DES-CBC-CRC or DES-CBC-MD5 is enabled, or the account uses DES keys only | 2 | High |
| Neither AES128 nor AES256 is enabled, or the controller has no value | 3 | Medium |
| RC4 is enabled | 4 | Low |

#### Remediation action

Configure the algorithms with the security option "Network security: Configure encryption types allowed for Kerberos" (Computer Configuration, Windows Settings, Security Settings, Local Policies, Security Options), in the "Default Domain Controller Policy" or another GPO that applies to all domain controllers. Do not change the setting in the local policy of each controller, which risks a desynchronization, and do not edit the `msDS-SupportedEncryptionTypes` attribute directly.

- To remove DES and the absence of AES (levels 2 and 3), enable RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1 and "Future encryption types".
- To also remove RC4 (level 4), enable AES128_HMAC_SHA1, AES256_HMAC_SHA1 and "Future encryption types".

Before the change, check that the domain controllers only issue tickets with AES encryption: in the security event log of each controller, events 4768 (TGT requests) and 4769 (service ticket requests) show the algorithm in the `TicketEncryptionType` field, and only 0x11 (AES128-CTS-HMAC-SHA1-96) and 0x12 (AES256-CTS-HMAC-SHA1-96) should appear. A controller updates its `msDS-SupportedEncryptionTypes` attribute from the policy when it restarts.

#### How the test works

The test finds the computer accounts of the domain controllers, writable and read-only, and reads their `msDS-SupportedEncryptionTypes` value. It reports a controller when the value enables DES (bits 0x1 or 0x2), enables neither AES128 (0x8) nor AES256 (0x10), or enables RC4 (0x4). A controller whose account is set to use DES keys only is reported at level 2. A controller without a value is reported at level 3, but not as RC4: the algorithm it uses then depends on its configuration.

The attribute is the one the controller publishes about itself. The test does not read the security option, the `DefaultDomainSupportedEncTypes` registry value of the controllers, or the algorithms that the tickets actually use, and it does not look at the domain functional level. The test is skipped when no domain controller computer account is in the collected data, or when the computers do not carry the attribute.

A passing result is reported with the most severe level the test can raise, High.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: DC/RODC supported encryption algorithms](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dc_crypto)
- [Microsoft: Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft: Network security: Configure encryption types allowed for Kerberos](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Microsoft: Kerberos protocol registry entries and KDC configuration keys in Windows](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys)

<!--- Results --->

%TestResult%
