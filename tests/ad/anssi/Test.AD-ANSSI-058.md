This test checks that the users, computers, groups, organizational units and GPOs of the domain are owned by the domain's administrators.

Every object in Active Directory has an owner, and the owner can always change the object's permissions, whatever they currently say. By default the owner is the account that created the object (or Domain Admins when an administrator created it), so a helpdesk account that created users, or a service account that joined computers to the domain, keeps that power over them for good. An attacker who takes over such an account can grant itself full control over the objects it owns, quietly and without any group change. ANSSI expects only Domain Admins, Enterprise Admins, Administrators or SYSTEM to own these objects.

#### Remediation action

For each owner listed in the results, check whether that account should really be able to take control of those objects. If not, give the objects back to Domain Admins, for example with Active Directory Users and Computers (Properties, Security, Advanced, Owner), or in PowerShell:

```powershell
$object = Get-ADObject -Identity '<distinguished name>'
$acl = Get-Acl -Path "AD:$($object.DistinguishedName)"
$acl.SetOwner([System.Security.Principal.NTAccount]'<DOMAIN>\Domain Admins')
Set-Acl -Path "AD:$($object.DistinguishedName)" -AclObject $acl
```

Then make it a habit: when delegated accounts create objects, reset the owner afterwards, or have the objects created by an administrative process.

#### How the test works

The test reads, for every user (which includes computers and managed service accounts), group, organizational unit and GPO of the domain, the owner part of its security descriptor, and its creation date. It ignores objects created in the last 7 days, and fails for each older object whose owner is not Domain Admins (the domain SID followed by 512), Enterprise Admins (RID 519), Administrators (S-1-5-32-544) or SYSTEM (S-1-5-18). An object whose owner could not be read is reported too, with an empty SID. The results group the objects by owner, the owners with the most objects first, with up to 3 example objects each.

Some things are not checked:

- other kinds of objects, such as containers, contacts or DNS records;
- the permissions the owners have been given on top of ownership;
- objects of other domains of the forest.

Enterprise Admins is a group of the forest root domain; since that domain's SID is not collected, any owner ending in 519 is accepted. If the owners cannot be read, the test is skipped rather than passing.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Incorrect object owners](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_owner)
- [Microsoft Learn: Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)

<!--- Results --->

%TestResult%
