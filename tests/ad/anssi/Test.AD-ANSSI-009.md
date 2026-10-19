This test checks that no domain controller is configured to accept resource-based constrained delegation.

Resource-based constrained delegation is set on the target of the delegation, in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of its account: a security descriptor that lists the accounts allowed to request tickets to that target on behalf of users. For this kind of delegation the domain controllers always allow protocol transition, so an allowed account can obtain a ticket to the target in the name of any user it chooses. When the target is a domain controller, anyone who controls an allowed account can reach the domain controller as a domain administrator and take over the domain. Setting the attribute does not take domain administrator rights, only the right to change it on that account, so it deserves close watch.

#### Remediation action

Remove the attribute from the computer account of each domain controller in the result, for example with `Set-ADComputer <DC> -PrincipalsAllowedToDelegateToAccount $null`. Then find out who set it and when, and review the accounts it allowed: an unexplained value is a likely trace of an attack.

#### How the test works

The test finds the computer accounts of the domain controllers, writable and read-only, and fails when one of them has the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, whatever accounts it allows. The result names the allowed accounts when they are in the collected data and shows their SID otherwise. The security descriptor is read byte by byte, so the test works on every platform; a descriptor that cannot be read still counts as set.

Only domain controllers are evaluated: resource-based delegation configured on other privileged servers, or on accounts other than computers, is not checked. The test is skipped when no domain controller computer account is found, or when the attribute was not collected.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Resource-based constrained delegation on privileged services](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_delegation_sourcedeleg)
- [Microsoft: Kerberos constrained delegation overview, resource-based constrained delegation](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Making the second hop in PowerShell Remoting, PrincipalsAllowedToDelegateToAccount](https://learn.microsoft.com/powershell/scripting/security/remoting/ps-remoting-second-hop)

<!--- Results --->

%TestResult%
