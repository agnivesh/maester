function Test-MtAnssiAdGroupNestingLoop {
    <#
    .SYNOPSIS
    ANSSI-AD-073: Group nesting should not contain loops.

    .DESCRIPTION
    Fails when groups are, through nesting, members of each other (for example A in B and B in
    A), or when a group is a member of itself. Such loops do not grant extra rights in Active
    Directory, but they can confuse the tools used to review who belongs to which group.

    The test is skipped when no group is in the collected data, or when the parent groups of a
    group were only partly returned.

    Corresponds to the ANSSI Active Directory checkpoint vuln_group_loop.

    .EXAMPLE
    Test-MtAnssiAdGroupNestingLoop

    Returns $true when group nesting has no loop, $false when it has one, and $null when the test
    is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdGroupNestingLoop
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-073',
        Title = 'Group nesting should not contain loops',
        Product = 'ad',
        Feature = 'groups',
        Area = 'identity-lifecycle',
        ResourceType = 'Group',
        Severity = 'Low',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdGroupNestingLoop'

    $adState = Get-MtADDomainState -Categories @('Groups')

    $groups = @($adState.Groups)
    $partial = @($groups | Where-Object { $null -eq $_.MemberOf })
    if ($groups.Count -eq 0 -or $partial.Count -gt 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No group was found in the collected data, or the parent groups of ' +
            "$($partial.Count) group(s) were only partly returned.")
        return $null
    }

    $loops = @(Get-MtAnssiAdGroupLoop -Group $groups)
    Write-Verbose "Groups: $($groups.Count), nesting loops: $($loops.Count)"

    if ($loops.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "Group nesting has no loop among the $($groups.Count) groups.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $loops -Column ([ordered]@{
            'Groups in the loop' = { @($_.Group | ForEach-Object { $_.Name }) -join ', ' }
            'Size'               = { @($_.Group).Count }
        })

    $result = "Group nesting has $($loops.Count) loop(s): the groups of each loop are, through " +
        "nesting, members of each other.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
