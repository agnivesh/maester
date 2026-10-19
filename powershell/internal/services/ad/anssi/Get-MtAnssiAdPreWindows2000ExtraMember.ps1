function Get-MtAnssiAdPreWindows2000ExtraMember {
    <#
    .SYNOPSIS
    Finds the members of Pre-Windows 2000 Compatible Access that are not the default member.

    .DESCRIPTION
    The only default member ANSSI accepts is Authenticated Users (S-1-5-11). Every other member is
    returned with the identity it represents.

    Authenticated Users, Everyone, Anonymous Logon and other well-known identities are members
    through a foreign security principal, an object named by the SID, so their SID is read from
    the distinguished name. Any other member is an account or a group of the domain, whose SID is
    not part of the name: it is returned without a SID.

    .PARAMETER Member
    The distinguished names of the direct members of the group.

    .EXAMPLE
    Get-MtAnssiAdPreWindows2000ExtraMember -Member $members

    Returns one object with DistinguishedName, Sid and Identity for each additional member.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [string[]] $Member
    )

    $wellKnown = @{
        'S-1-1-0' = 'Everyone'
        'S-1-5-7' = 'Anonymous Logon'
    }
    $extra = [System.Collections.Generic.List[object]]::new()

    foreach ($distinguishedName in $Member) {
        $sid = $null
        $identity = 'Account or group of the domain'
        if ($distinguishedName -imatch '^CN=(S-1-[0-9-]+),CN=ForeignSecurityPrincipals,') {
            $sid = $Matches[1]
            if ($sid -eq 'S-1-5-11') {
                continue
            }
            $identity = 'Foreign security principal'
            if ($wellKnown.ContainsKey($sid)) {
                $identity = $wellKnown[$sid]
            }
        }

        $extra.Add([PSCustomObject]@{
                DistinguishedName = $distinguishedName
                Sid               = $sid
                Identity          = $identity
            })
    }

    return $extra.ToArray()
}
