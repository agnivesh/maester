This test checks that the domain was not left with the excess permissions that revision 15 of its domain preparation can create for the Key Admins groups.

Before a domain gets its first domain controller of a new Windows Server version, `adprep /domainprep` updates its permissions and records how far it got in the `revision` attribute of `CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System`. The preparation shipped with Windows Server 2016 stops at revision 15. ANSSI says this revision sets overly permissive entries for the Key Admins and Enterprise Key Admins groups on the domain root, where those groups only need to read and write the `msDS-KeyCredentialLink` attribute, and that it opens a path to taking over the domain. Revision 16, delivered with Windows Server version 1709 and later, replaces the excess with the narrow grant.

#### Remediation action

Run the domain preparation again from a recent Windows Server installation medium (Windows Server 2019 or later, for example): `adprep /forestprep`, then `adprep /domainprep`. This only updates permissions; it does not require upgrading the domain controllers or raising the functional level. Afterwards, check that the revision reads 16 or higher. If the entries listed in the result are the only problem, you can also remove the excess from the domain root by hand and keep the narrow read and write grant on `msDS-KeyCredentialLink`.

#### How the test works

The test reads the `revision` value of the domain preparation object. Any revision other than 15 passes: higher revisions contain the correction, and lower ones come from older Windows Server versions, before the Key Admins groups existed.

At revision 15 the test also reads the permissions of the domain root. It looks at the Allow entries of the Key Admins group (relative ID 526) and the Enterprise Key Admins group (relative ID 527) of the domain, and it fails when one of them gives more than reading and writing `msDS-KeyCredentialLink`. An entry is broader when it allows any of: creating or deleting child objects, deleting the object or its tree, changing permissions, changing the owner, extended rights, generic write, full control, or writing any property other than `msDS-KeyCredentialLink` (an entry without an object type writes all of them). An entry that only inherits to the objects below still counts. Reading, listing and reading permissions do not. The result lists each broad entry with its group, mask and object type.

When the groups hold only the narrow right, the test passes and says so. This part is Maester's own reading: ANSSI's finding is based on the revision alone, but a domain prepared with a corrected build of Windows Server 2016, or fixed by hand, still reads revision 15 without the excess. In the Windows Server 2016 lab domain used to test this, the revision was 15 while both groups held only the narrow right. Preparing the domain again to reach revision 16 is still advised.

Some things are not checked: the permissions of other objects than the domain root, Deny entries, and domains other than the collected one. The test is skipped when the domain, the revision, or (at revision 15) the permissions of the domain root could not be read.

#### Related links

- [ANSSI Active Directory checkpoints: Bad Active Directory versions](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_adupdate_bad)
- [Microsoft: Domain-wide schema updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates)
- [Microsoft: adprep](https://learn.microsoft.com/windows-server/administration/windows-commands/adprep)

<!--- Results --->

%TestResult%
