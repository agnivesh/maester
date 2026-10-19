This test checks that no more than 10% of the enabled user accounts have a password that never expires.

Active Directory enforces periodic password changes only for accounts whose password is allowed to expire. A password that never expires stays the same until someone changes it by hand, and some of these passwords end up unchanged for more than 10 years, which increases the likelihood of exposure, reuse or weakness. The flag is often set on service accounts and shared accounts, for which no password change procedure is documented.

Should an attacker compromise one of these accounts, they would be able to maintain long-term access to the Active Directory domain.

#### Remediation action

**General case:** accounts must not have the `DONT_EXPIRE_PASSWORD` flag set, so that Active Directory enforces periodic password changes. Unset the flag, usually by clearing "Password never expires" in the Account tab of the user properties, then roll the passwords immediately.

```powershell
Set-ADAccountControl -Identity <account> -PasswordNeverExpires $false
```

Enforcing a short password lifespan may be counterproductive, but never-changing passwords should be avoided. If a long lifespan is accepted for a population of accounts, reflect it explicitly in the password policy through a Password Settings Object (PSO), so that the exception is documented and the organization is never at risk of being unable to change a specific password.

**Service accounts:** user accounts cannot technically be distinguished from non-managed (non-gMSA, non-sMSA) service accounts. Keep an up-to-date list of all service accounts, with for each:

- all information about the account (`sAMAccountName`, description, group membership, specificities);
- the applications or systems using it;
- the last time its password was changed;
- a procedure to change its password;
- a person or a team responsible for its lifecycle.

#### How the test works

The test reads the user accounts of the domain and keeps the enabled ones. It fails when more than 10% of them have `DONT_EXPIRE_PASSWORD` (`0x10000`) set in `userAccountControl`. Disabled accounts are ignored, in the count and in the total, because they cannot be used to log on.

The results list the accounts with the oldest password first, up to 100 accounts.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Accounts with never-expiring passwords](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_dont_expire)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
