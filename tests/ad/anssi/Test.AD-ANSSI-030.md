This test checks that only privileged principals can control the group policy objects (GPOs) that apply to privileged accounts.

A GPO that applies to an administrator account, or to a domain controller, runs on that account or computer: its logon scripts, scheduled tasks, software installations and security settings all take effect there. Whoever can change such a GPO, its file path, or its permissions can therefore run code as an administrator. ANSSI asks that every principal with such a control path be treated as an administrator itself.

#### Remediation action

Review the permissions of the GPOs listed in the results in the Group Policy Management Console (`gpmc.msc`), which keeps the permissions of the directory object and of its folder in SYSVOL in step, and remove the principals that are not administrators. If a principal must keep its rights, treat it, and every member of it, as a tier 0 administrator. Consider giving privileged accounts their own OU tree with GPOs managed by administrators only.

#### How the test works

The test works out the privileged accounts as the other ANSSI permission tests do: the members of the groups Active Directory protects with AdminSDHolder, followed through nested groups and primary groups, plus the built-in Administrator and krbtgt accounts. For each account it walks the OUs above it up to the domain root and collects the GPOs linked there, the way Windows applies them: a disabled link never applies, and above an OU that blocks inheritance only enforced links still apply.

It then reads the owner and the permissions of each GPO of the domain found this way and reports each right from a fixed list (changing the file path, writing all attributes, creating child objects, full control, changing the permissions or the owner, and the like) held by a principal outside the privileged set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. GPOs are named by their display name and their identifier. Every finding counts as Critical.

Some things are not checked:

- GPOs linked to sites;
- security filtering and WMI filters, so a GPO is reported even when it is filtered away from the privileged accounts;
- the permissions of the GPO folders in SYSVOL;
- GPOs of another domain linked to this one; the results say how many there were;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

If a read fails, or the permissions of a GPO cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no GPO applied to a privileged account is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose GPOs applied to privileged group members](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_gpo_priv)
- [Microsoft Learn: Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [Microsoft Learn: Group Policy scope](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-scope)

<!--- Results --->

%TestResult%
