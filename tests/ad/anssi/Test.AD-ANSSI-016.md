This test checks that the dSHeuristics attribute of the forest does not hold dangerous settings.

dSHeuristics is an attribute of the directory service configuration. Each character of its value is a setting at a fixed position that changes how Active Directory behaves. For instance:

- `fLDAPBlockAnonOps` (7th character) set to 2 allows unauthenticated LDAP operations;
- `fAllowAnonNSPI` (8th) controls anonymous access to the Name Service Provider Interface (NSPI);
- `dwAdminSDExMask` (16th) defines which groups are covered by the SDProp mechanism;
- `DoNotVerifyUPNAndOrSPNUniqueness` (21st) disables the checks on the uniqueness of UPNs and SPNs;
- `AttributeAuthorizationOnLDAPAdd` (28th) and `BlockOwnerImplicitRights` (29th) control the auditing and enforcement of the permission updates released with KB5008383 (CVE-2021-42291);
- `DisableConfidentialAttributeEncryptionRequirements` (31st) disables the encryption requirements for confidential attributes.

A dangerous value weakens a protection for the whole forest: it can allow anonymous access to the directory, change which groups are covered by the SDProp protection, or switch off the hardening introduced by the CVE-2021-42291 permission updates.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

The severity is the one of the most severe setting found.

| Setting found | ANSSI level | Severity |
| --- | --- | --- |
| `fAllowAnonNSPI` or `dwAdminSDExMask` is not 0 | 1 | Critical |
| `fLDAPBlockAnonOps` is 2 | 2 | High |
| `DoNotVerifyUPNAndOrSPNUniqueness` or `DisableConfidentialAttributeEncryptionRequirements` is not 0 | 2 | High |
| `AttributeAuthorizationOnLDAPAdd` or `BlockOwnerImplicitRights` is 2 | 2 | High |
| `AttributeAuthorizationOnLDAPAdd` or `BlockOwnerImplicitRights` is not 1 | 4 | Low |

#### Remediation action

Reset the dangerous settings to their default value:

- `fLDAPBlockAnonOps` should not be set, or should have any value other than 2;
- `fAllowAnonNSPI` should be 0;
- `dwAdminSDExMask` should be 0;
- `DoNotVerifyUPNAndOrSPNUniqueness` should be 0;
- `DisableConfidentialAttributeEncryptionRequirements` should be 0;
- `AttributeAuthorizationOnLDAPAdd` and `BlockOwnerImplicitRights` should not be 2, and should be explicitly set to 1 to get the full hardening.

For example, the value `0000000001000000000200000001130` has every setting at its default except `BlockOwnerImplicitRights` and `AttributeAuthorizationOnLDAPAdd`, which are set to 1.

The fix is usually applied with `adsiedit.msc` on the `CN=Directory Service,CN=Windows NT,CN=Services` object of the configuration partition. Only change the characters you need to: the order of the characters is fixed and the values of the existing characters that are not concerned by the change must be preserved.

#### How the test works

The test reads the dSHeuristics value from the directory configuration and checks the characters at the positions above. A missing character, because the value is shorter or the attribute is not set, has the default 0. For `AttributeAuthorizationOnLDAPAdd` and `BlockOwnerImplicitRights` the effective value is used: a character other than 0 to 3 counts as 1.

A setting that matches several rules is reported once, with its most severe level. Because the two hardening settings must be explicitly 1, a forest that has not set them gets a Low finding.

When the directory configuration is not in the collected data, the test is skipped.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous dsHeuristics settings](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dsheuristics_bad)
- [MS-ADTS: dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5)
- [KB5008383: Active Directory permissions updates (CVE-2021-42291)](https://support.microsoft.com/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1)

<!--- Results --->

%TestResult%
