This test checks that every enabled user account requires Kerberos preauthentication.

Kerberos preauthentication ensures that a user requesting a Ticket Granting Ticket (TGT) knows a given authentication secret. By default, all user accounts require it, because their `DONT_REQ_PREAUTH` property is not set. The property exists for backward compatibility with older Kerberos implementations.

Without preauthentication, anyone can request a ticket encrypted with one of the Kerberos keys of the account, without knowing its password. It is then possible to carry out a brute force or dictionary attack offline to crack the password of the account, if it is not strong enough.

#### Remediation action

**General case:** remove the `DONT_REQ_PREAUTH` property from the accounts listed in the results. If an application is not compatible with this change, upgrade it.

```powershell
Set-ADAccountControl -Identity <account> -DoesNotRequirePreAuth $false
```

**Specific cases:** any incompatible software must be upgraded. Until then, the risk can be reduced as follows:

- define a refined password policy through Password Settings Objects (PSO) that enforces a minimum password length of 32 characters;
- define a refined password policy through PSO that enforces a maximum password age of 3 years;
- change the passwords of the affected accounts after modifying the PSO settings;
- enforce AES for the affected accounts.

#### How the test works

The test reads the user accounts of the domain and reports the enabled accounts that have `DONT_REQ_PREAUTH` (`0x400000`) set in `userAccountControl`. Disabled accounts are ignored, because the key distribution center does not answer for them.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Kerberos preauthentication disabled](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_kerberos_properties_preauth)
- [Microsoft Learn: Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft Learn: Set-ADAccountControl](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountcontrol)

<!--- Results --->

%TestResult%
