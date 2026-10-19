This test checks that no enabled user account is restricted to the DES encryption types of Kerberos.

The `USE_DES_KEY_ONLY` flag allows domain controllers to issue Kerberos tickets encrypted with the DES algorithm for an account. The flag exists for backward compatibility with older Kerberos implementations. DES is considered weak and must not be used anymore: a key length of 56 bits means that the encrypted content can be broken with little effort.

An account with this flag significantly weakens the security of the Kerberos tickets that are distributed for it and speeds up brute force cracking attempts of its password.

#### Remediation action

Unset the `USE_DES_KEY_ONLY` flag from the `userAccountControl` attribute of each account listed in the results. This is done by clearing "Use Kerberos DES encryption types for this account" in the account properties, or with:

```powershell
Set-ADAccountControl -Identity <account> -UseDESKeyOnly $false
```

Any software that is incompatible with this change must be upgraded.

#### How the test works

The test reads the user accounts of the domain and reports the enabled accounts that have `USE_DES_KEY_ONLY` (`0x200000`) set in `userAccountControl`. Disabled accounts are ignored, because no ticket is issued for them.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Use of Kerberos with weak encryption](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_kerberos_properties_deskey)
- [Microsoft Learn: Remove the highly insecure DES encryption from the user accounts](https://learn.microsoft.com/services-hub/microsoft-engage-center/health/remediation-steps-ad/remove-the-highly-insecure-des-encryption-from-user-accounts)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
