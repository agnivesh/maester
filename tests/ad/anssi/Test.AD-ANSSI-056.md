This test checks that the built-in group Pre-Windows 2000 Compatible Access has no member other than Authenticated Users.

The group served backward compatibility for systems older than Windows 2000, in practice Windows NT 4.0. Members of the group other than the default ones are granted access to some RPC calls. Depending on a system parameter, Everyone can include anonymous users, so having Everyone in the group can extend that access to unauthenticated users, which lets an attacker enumerate directory information.

#### Remediation action

The group should only include Authenticated Users (S-1-5-11), which is the default when the domain was set up in the Windows 2000-only permissions mode. Remove the other members, for example with Active Directory Users and Computers or `net localgroup "Pre-Windows 2000 Compatible Access" <member> /delete`. Before the change, check that no Windows NT 4.0 system or application still relies on them. The change is easily reversible.

Servers of the Active Directory Certificate Services (AD CS) role are added to the group when the role is installed. In most cases the membership is not useful and can be removed.

#### How the test works

The test finds the group by its well-known SID, S-1-5-32-554, so it works regardless of the language of the domain. It reads the direct members of the group from the `member` attribute and fails when at least one of them is not Authenticated Users. Authenticated Users, Everyone and Anonymous Logon are members through a foreign security principal named after their SID, such as `CN=S-1-5-11,CN=ForeignSecurityPrincipals`. Any other member is an account or a group of the domain. The result lists each additional member with the identity it represents.

Anonymous Logon in the group is reported here too, as an additional member. It is also the subject of the more severe test ANSSI-AD-039, so a domain that has it fails both tests.

An empty group passes: the test only forbids additional members. Only direct members are evaluated, a nested membership is not followed. The test is skipped when the group is not in the collected data, or when its members cannot be read, because an unknown membership is not a safe one.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Use of the "Pre-Windows 2000 Compatible Access" group](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_compatible_2000_not_default)
- [Microsoft: Active Directory security groups, Pre-Windows 2000 Compatible Access](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#default-security-groups)
- [Microsoft: Well-known SIDs](https://learn.microsoft.com/windows/win32/secauthz/well-known-sids)
- [Microsoft: Requirements for Network Management Functions on Active Directory Domain Controllers](https://learn.microsoft.com/windows/win32/netmgmt/requirements-for-network-management-functions-on-active-directory-domain-controllers)

<!--- Results --->

%TestResult%
