This test checks that no group is, through nesting, a member of itself.

Groups can be put inside other groups, and Active Directory follows that nesting when it works out who belongs to what. When group A is in group B and group B is back in group A (directly or through more groups), the nesting goes round in a loop. Windows copes with it and no extra rights come from it, but it is almost always a mistake, and it makes membership hard to reason about. Some audit and management tools stop with an error or never finish on such loops, which can hide who really is in a privileged group.

#### Remediation action

For each loop listed in the results, decide which nesting is the intended one and remove the membership that closes the loop, for example:

```powershell
Remove-ADGroupMember -Identity <parent group> -Members <child group>
```

Then check that the members of each group in the loop still get the access they need.

#### How the test works

The test reads every group of the domain with the groups it is directly a member of (its `memberOf` attribute), builds the nesting between them, and looks for groups that can reach themselves through it. Each set of groups that are members of each other is reported once as a loop, with its size; a group that is a member of itself is a loop of one. A group that only leads into a loop, without being part of it, is not reported.

Some things are not checked:

- nesting through groups of other domains or forests, which are not collected;
- nesting through a primary group, which only users and computers have.

If no group was collected, or if the domain controller returned only part of a group's parent groups (which can happen when a group belongs to very many groups), the test is skipped rather than reporting on incomplete data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Loops in group memberships](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_group_loop)
- [Microsoft Learn: Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft Learn: Remove-ADGroupMember](https://learn.microsoft.com/powershell/module/activedirectory/remove-adgroupmember)

<!--- Results --->

%TestResult%
