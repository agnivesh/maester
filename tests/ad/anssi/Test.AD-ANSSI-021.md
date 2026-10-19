This test checks that every enabled privileged account has changed its password in the last 3 years.

Passwords leak in many quiet ways: a reused password in a breach, a script on a file share, a former administrator who still remembers it. The longer a privileged password stays the same, the more chances it has had to end up in the wrong hands, and the longer whoever has it can keep using it. The built-in Administrator account, kept for emergencies, is the one most often forgotten.

#### Remediation action

Change the password of each account listed in the results, starting with the oldest. For the built-in Administrator account, check while doing so that the emergency procedure still works and is still written down.

Then make sure it does not happen again: let the domain password policy, or a fine-grained password policy for privileged accounts, make these passwords expire, and clear "Password never expires" on them. There is no need to go to short lifetimes: forcing frequent changes pushes people towards weaker passwords. A few years at most is what ANSSI asks for.

Accounts that nobody uses any more should be disabled, removed from their groups and given a random password.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

It then fails for each enabled privileged user account whose password was last set more than 3 years before the test runs, or that has no password change date at all. The results give the cutoff date and list those accounts with the oldest password first.

Some things are not checked:

- computer accounts, which change their own passwords (domain controllers have tests of their own);
- disabled accounts;
- members that live outside the collected domain, for example in another domain of the forest. The results say how many there were.

If a protected group cannot be read, the test is skipped rather than passing on a partial list.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged account passwords age too old](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_priv)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Microsoft Learn: Configure fine grained password policies](https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies)

<!--- Results --->

%TestResult%
