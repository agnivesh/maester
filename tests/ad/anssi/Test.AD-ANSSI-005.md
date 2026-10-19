This test checks that the objects every privilege review depends on can be found and their permissions read.

The other checks of this suite, and any audit of who can control the domain, rely on a handful of objects: the AdminSDHolder template, the built-in Administrator and krbtgt accounts, Domain Admins and, in the forest root domain, Schema Admins and Enterprise Admins. When the account running the scan cannot see one of them, or cannot read its permissions, those checks are blind for it. This does not point at a vulnerability by itself. It means that someone changed the permissions of these objects, which may be a deliberate attempt to hide them, or that the scan ran with too few rights.

#### What ANSSI says and how it rates the risk

ANSSI describes this finding from the point of view of its assessment tool: the tool needs information about objects such as AdminSDHolder, krbtgt, Administrator, Domain Admins, Schema Admins and Enterprise Admins, and raises level 1 when it cannot read them.

A missing or unreadable critical object points to a broken or tampered directory, but it is a data availability check and not a weakness that can be used directly, so Maester rates it Medium.

#### Remediation action

Run the scan again with an account allowed to read the whole directory, for example a member of Domain Admins; when it runs on a domain controller, use an elevated session so that User Account Control does not filter the account's groups. If the objects are still missing or unreadable, look at their permissions, and at those of the containers above them, for deny entries or removed read rights, and restore the defaults.

#### How the test works

The test looks for the accounts with RID 500 (Administrator) and 502 (krbtgt) and the group with RID 512 (Domain Admins) in the collected users and groups, and, when the domain is the forest root, the groups with RID 518 (Schema Admins) and 519 (Enterprise Admins). An object that is not there is reported as not found. It then reads the security descriptor (owner and permissions) of each object found and of `CN=AdminSDHolder,CN=System` of the domain, one LDAP read each, and reports those whose descriptor does not come back.

Some things are not checked:

- Schema Admins and Enterprise Admins from a child domain: they live in the forest root domain, which is not collected;
- other attributes of these objects, such as group members;
- the audit part of the descriptors (SACL).

If a read fails outright, for example when AdminSDHolder cannot be seen at all, the test is skipped rather than reporting a result.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Critical objects unavailable](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_critical_objects)
- [Microsoft Learn: Appendix C, Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

<!--- Results --->

%TestResult%
