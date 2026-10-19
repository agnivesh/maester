function Get-MtAnssiAdTrustedSid {
    <#
    .SYNOPSIS
    Builds the set of SIDs whose rights on sensitive objects are expected.

    .DESCRIPTION
    Returns a case-insensitive set holding the SIDs of the privileged accounts and of every group
    walked to find them (Get-MtAnssiAdPrivilegedAccount: the AdminSDHolder-protected groups and
    the groups nested in them), plus Local System (S-1-5-18), Enterprise Domain Controllers
    (S-1-5-9), Principal Self (S-1-5-10), Administrators (S-1-5-32-544) and the domain groups
    Domain Admins (512), Domain Controllers (516), Read-only Domain Controllers (521) and Key
    Admins (526). Microsoft grants these rights by default. The forest-wide groups (498, 518, 519,
    527) are trusted by Select-MtAnssiAdUntrustedSid for any domain.

    .PARAMETER Privileged
    The result of Get-MtAnssiAdPrivilegedAccount (Account and Group lists).

    .PARAMETER Group
    The collected groups, used to find the SID of each walked group.

    .PARAMETER DomainSid
    The SID of the domain.

    .PARAMETER ForestRootSid
    The SID of the forest root domain. Give it when a test judges objects that belong to the whole
    forest and may run from a child domain: the same four domain groups (512, 516, 521, 526) of
    the forest root domain are then trusted too, as they are when the test runs from the root.
    Leave it out for objects of the domain itself.

    .EXAMPLE
    Get-MtAnssiAdTrustedSid -Privileged $privileged -Group $adState.Groups -DomainSid $domainSid

    Returns the trusted SIDs.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]], [object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Privileged,

        [AllowNull()]
        [object[]] $Group,

        [Parameter(Mandatory)]
        [string] $DomainSid,

        [string] $ForestRootSid
    )

    $trusted = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in 'S-1-5-18', 'S-1-5-9', 'S-1-5-10', 'S-1-5-32-544') {
        $null = $trusted.Add($sid)
    }
    foreach ($rid in 512, 516, 521, 526) {
        $null = $trusted.Add("$DomainSid-$rid")
        if ($ForestRootSid) { $null = $trusted.Add("$ForestRootSid-$rid") }
    }
    foreach ($account in $Privileged.Account) {
        $null = $trusted.Add([string]$account.Item.Sid.Value)
    }

    $walked = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($Privileged.Group), [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Group) {
        if ($walked.Contains([string]$item.DistinguishedName)) {
            $null = $trusted.Add([string]$item.Sid.Value)
        }
    }
    return , $trusted
}
