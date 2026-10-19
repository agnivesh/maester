This test checks that the domain does not store passwords with reversible encryption.

The `pwdProperties` attribute, at the root of the domain, imposes password properties on the whole domain. When its `DOMAIN_PASSWORD_STORE_CLEARTEXT` flag (value 16) is set, the passwords changed after the flag was set are stored in a reversible way. An attacker who obtains a copy of the directory can then recover the passwords themselves, not only their hashes.

The properties of the attribute are:

| Flag | Value |
| --- | --- |
| `DOMAIN_PASSWORD_COMPLEX` | 1 |
| `DOMAIN_PASSWORD_NO_ANON_CHANGE` | 2 |
| `DOMAIN_PASSWORD_NO_CLEAR_CHANGE` | 4 |
| `DOMAIN_LOCKOUT_ADMINS` | 8 |
| `DOMAIN_PASSWORD_STORE_CLEARTEXT` | 16 |
| `DOMAIN_REFUSE_PASSWORD_CHANGE` | 32 |

By default, the value is 0 and the attribute has no effect on the password policy.

#### Remediation action

Clear the `DOMAIN_PASSWORD_STORE_CLEARTEXT` flag, for example by disabling the `Store passwords using reversible encryption` setting of the domain password policy, or with the Active Directory PowerShell module:

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ReversibleEncryptionEnabled $false
```

This does not protect the passwords that are already stored in a reversible way: they stay recoverable until they are changed. Rotate the affected passwords after the setting is corrected.

Only enable the setting when an application really requires it, for example Challenge Handshake Authentication Protocol (CHAP) through remote access or Internet Authentication Service, or Digest Authentication in Internet Information Services.

#### How the test works

The test reads the `pwdProperties` attribute of the domain object and fails when the value has the flag 16. The other flags are not evaluated.

The test covers the setting of the domain root only. Fine-grained password policies and the per-account `ENCRYPTED_TEXT_PWD_ALLOWED` option are not evaluated.

The test is skipped when the domain object or the attribute is not in the collected data.

#### Related links

- [ANSSI Active Directory checkpoints: Passwords stored in cleartext because of a configuration at the naming context root](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_reversible_password_priv_namingcontext)
- [Microsoft: Store passwords using reversible encryption](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)
- [Microsoft: Pwd-Properties attribute](https://learn.microsoft.com/windows/win32/adschema/a-pwdproperties)
- [Microsoft: Set-ADDefaultDomainPasswordPolicy](https://learn.microsoft.com/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy)

<!--- Results --->

%TestResult%
