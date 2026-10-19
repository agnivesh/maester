This test checks that the built-in group Pre-Windows 2000 Compatible Access does not include the Anonymous Logon identity.

The Pre-Windows 2000 compatibility mechanism keeps Windows NT 4.0 domains supported. It is enabled by adding the Anonymous Logon identity (S-1-5-7) to the Pre-Windows 2000 Compatible Access group (S-1-5-32-554). This membership allows anonymous access to some of the content of Active Directory on the domain controllers, which lets an unauthenticated attacker enumerate directory information.

#### Remediation action

The group served backward compatibility for systems older than Windows 2000, in practice Windows NT 4.0. It should only include Authenticated Users (S-1-5-11), which is the default when the domain was set up in the Windows 2000-only permissions mode.

Remove Anonymous Logon from the group, for example with `net localgroup "Pre-Windows 2000 Compatible Access" "Anonymous Logon" /delete` on a domain controller, or with Active Directory Users and Computers. Before the change, check that no Windows NT 4.0 system or application still relies on anonymous access to the directory. The change is easily reversible.

#### How the test works

The test finds the group by its well-known SID, S-1-5-32-554, so it works regardless of the language of the domain. It reads the direct members of the group from the `member` attribute and fails when one of them is the foreign security principal named after the Anonymous Logon SID, `CN=S-1-5-7,CN=ForeignSecurityPrincipals`.

Only direct members are evaluated: a membership of Anonymous Logon through another group nested in this one is not detected. Other additional members of the group, such as Everyone, are not evaluated by this test. The test is skipped when the group is not in the collected data, or when its members cannot be read, because an unknown membership is not a safe one.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: The "Pre-Windows 2000 Compatible Access" group includes "Anonymous"](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_compatible_2000_anonymous)
- [Microsoft: Active Directory security groups, Pre-Windows 2000 Compatible Access](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#default-security-groups)
- [Microsoft: Well-known SIDs](https://learn.microsoft.com/windows/win32/secauthz/well-known-sids)
- [Microsoft: Requirements for Network Management Functions on Active Directory Domain Controllers](https://learn.microsoft.com/windows/win32/netmgmt/requirements-for-network-management-functions-on-active-directory-domain-controllers)

<!--- Results --->

%TestResult%
