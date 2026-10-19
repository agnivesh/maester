This test checks that the domain rotates the password of accounts that require a smart card.

When an account is set to require a smart card for interactive logon, its password hash is replaced with a random value. Without automatic rotation that value never changes, so the hash of such an account stays valid for as long as the account exists, and a stolen hash can be used to authenticate indefinitely. From the Windows Server 2016 domain functional level, the domain controllers can roll these secrets automatically, which follows the password policy of the domain. The rotation is enforced when the attribute `msDS-ExpirePasswordsOnSmartCardOnlyAccounts` is TRUE on the root of the domain.

#### Remediation action

Set the attribute `msDS-ExpirePasswordsOnSmartCardOnlyAccounts` to TRUE on the root object of each domain, even if smart cards are not used at the moment, so that the rotation applies to accounts that are configured later. For example, from a domain controller with the Active Directory module:

```powershell
Set-ADObject -Identity (Get-ADDomain).DistinguishedName -Replace @{ 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' = $true }
```

The attribute only takes effect at the Windows Server 2016 domain functional level.

#### How the test works

The test reads the attribute on the domain object and passes when its value is TRUE. A value of FALSE, or an attribute that is not set, fails the test.

The attribute is only effective at the Windows Server 2016 domain functional level, so the test is skipped when the functional level is lower; the functional level itself is reported by ANSSI-AD-017. The test is also skipped when the domain or its functional level is not in the collected data.

An attribute that cannot be read looks the same as an attribute that is not set, so the test fails in both cases. Authenticated users can read the attribute on the domain object by default. The test does not check whether the domain has any account that requires a smart card, and it does not check the password policy that the rotation follows. Microsoft Learn describes the rotation at the Windows Server 2016 functional level but does not document this attribute itself; the attribute name and its location on the domain root are taken from the ANSSI recommendation.

#### Related links

- [ANSSI Active Directory checkpoints: Missing password expiration for smart card users](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_smartcard_expire_passwords)
- [Microsoft: Active Directory Domain Services functional levels](https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels)
- [Microsoft: Active Directory accounts, Smart card is required for interactive logon](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-default-user-accounts)

<!--- Results --->

%TestResult%
