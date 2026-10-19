This test checks that the password of every trust account has been changed within the last year.

A trust account is the user account, whose name ends with a dollar sign, that holds the secret shared with the other side of a trust relationship. Between Microsoft environments the trust password is changed automatically, so an old password is not expected.

A trust password that has not changed for more than a year points to one of two situations: the trust relationship was deleted while its account remained, or the automatic password change of an active trust does not work. An abandoned account is not monitored by anyone, and an unrenewed trust password stays valid for as long as it is known. A party holding it could keep forging tickets that cross the trust.

#### Remediation action

For each trust account listed in the results, find out which situation applies:

- **Deleted trust relationship:** the account remains while its trust relationship was removed. Delete the account manually.
- **Active trust relationship:** trust passwords should be changed at least once a year, and that change must be automatic between Microsoft environments. Investigate why the automatic renewal does not happen.

#### How the test works

The test reads the user accounts of the domain. A trust account is an account with `INTERDOMAIN_TRUST_ACCOUNT` (`0x800`) set in `userAccountControl`. It is reported when its `pwdLastSet` is more than one year old, or when the password was never set. Disabled trust accounts are reported too.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Trust account passwords unchanged for more than a year](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_trusts_accounts)

<!--- Results --->

%TestResult%
