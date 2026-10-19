This test checks that the password policy applied to each enabled privileged account asks for decent passwords.

A domain can apply different password rules to different accounts through fine-grained password policies. That is useful for giving administrators stricter rules than everyone else, but it also makes it easy to end up with the opposite: an old policy, created for a legacy application, that lets an administrator keep a short password forever. A short password can be guessed or cracked quickly, and one that never has to change stays useful to whoever learned it.

#### Remediation action

Make sure every privileged account gets a policy that requires at least 8 characters (much longer is better for administrators) and makes passwords expire at least every 3 years. Do not go to very short lifetimes: forcing frequent changes pushes people towards weaker, predictable passwords.

The simplest way is a fine-grained password policy that applies to a group holding all administrators, with a high precedence (a low number) so that it wins over other policies:

```powershell
New-ADFineGrainedPasswordPolicy -Name 'Administrators' -Precedence 10 -MinPasswordLength 15 `
    -MaxPasswordAge '365.00:00:00' -ComplexityEnabled $true
Add-ADFineGrainedPasswordPolicySubject -Identity 'Administrators' -Subjects 'Domain Admins'
```

Then check which policy each listed account really gets, for example in Active Directory Administrative Center ("View resultant password settings") or with `Get-ADUserResultantPasswordPolicy`.

#### How the test works

The test first works out which accounts are privileged. It starts from the groups that Active Directory protects with AdminSDHolder: Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Replicator, Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins, plus Schema Admins, Enterprise Admins and Enterprise Key Admins in the forest root domain. It then reads their members over LDAP, follows nested groups, and adds accounts whose primary group is one of these groups. The built-in Administrator and krbtgt accounts always count.

For each enabled privileged user account it then reads `msDS-ResultantPSO`, which the domain controller fills with the fine-grained password policy that wins for that account, and reads that policy. An account without one gets the domain password policy. The test fails when the policy allows passwords shorter than 8 characters, or passwords that never expire (no maximum age, or 0) or may stay unchanged for more than 3 years. The results list each account with its policy and what is weak about it.

Some things are not checked:

- the "Password never expires" setting on the account itself, which another test covers;
- complexity, history and lockout settings;
- computer accounts and disabled accounts;
- members that live outside the collected domain. The results say how many there were.

If a fine-grained password policy cannot be read, which can happen when the test runs with an account that is not an administrator, the test is skipped and says so. If the account running the test cannot see `msDS-ResultantPSO`, the domain password policy is judged instead.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Privileged group members with weak password policy](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_privileged_members_password)
- [Microsoft Learn: Configure fine grained password policies](https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies)
- [Microsoft Learn: ms-DS-Resultant-PSO attribute](https://learn.microsoft.com/windows/win32/adschema/a-msds-resultantpso)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

<!--- Results --->

%TestResult%
