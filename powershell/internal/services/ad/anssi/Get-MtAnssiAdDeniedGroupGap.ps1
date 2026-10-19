function Get-MtAnssiAdDeniedGroupGap {
    <#
    .SYNOPSIS
    Finds the default members missing from the Denied RODC Password Replication Group.

    .DESCRIPTION
    The Denied RODC Password Replication Group (domain RID 572) should hold Domain Controllers
    (516), Read-only Domain Controllers (521), Group Policy Creator Owners (520), Domain Admins
    (512), Cert Publishers (517) and the krbtgt account (502) of the domain. In the forest root
    domain it should also hold Schema Admins (518) and Enterprise Admins (519); in another domain
    those groups belong to the root domain and are not checked.

    Returns the names of the expected members whose SID is not among the given member SIDs, in
    the order above.

    .PARAMETER MemberSid
    The SIDs of the direct members of the group.

    .PARAMETER DomainSid
    The SID of the domain.

    .PARAMETER IsForestRoot
    The domain is the forest root domain.

    .EXAMPLE
    Get-MtAnssiAdDeniedGroupGap -MemberSid $sids -DomainSid $domainSid -IsForestRoot

    Returns the names of the missing default members.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [string[]] $MemberSid,

        [Parameter(Mandatory)]
        [string] $DomainSid,

        [switch] $IsForestRoot
    )

    $expected = [System.Collections.Generic.List[object]]::new()
    $expected.Add(@{ Rid = 516; Name = 'Domain Controllers' })
    $expected.Add(@{ Rid = 521; Name = 'Read-only Domain Controllers' })
    $expected.Add(@{ Rid = 520; Name = 'Group Policy Creator Owners' })
    $expected.Add(@{ Rid = 512; Name = 'Domain Admins' })
    $expected.Add(@{ Rid = 517; Name = 'Cert Publishers' })
    $expected.Add(@{ Rid = 502; Name = 'krbtgt' })
    if ($IsForestRoot) {
        $expected.Add(@{ Rid = 518; Name = 'Schema Admins' })
        $expected.Add(@{ Rid = 519; Name = 'Enterprise Admins' })
    }

    $missing = foreach ($item in $expected) {
        if ($MemberSid -notcontains "$DomainSid-$($item.Rid)") {
            $item.Name
        }
    }

    return @($missing)
}
