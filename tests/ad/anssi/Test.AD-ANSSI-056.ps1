function Test-MtAnssiAdPreWindows2000AdditionalMember {
    <#
    .SYNOPSIS
    ANSSI-AD-056: Pre-Windows 2000 Compatible Access should only include Authenticated Users.

    .DESCRIPTION
    Fails when the built-in group Pre-Windows 2000 Compatible Access (S-1-5-32-554) has a direct
    member other than Authenticated Users (S-1-5-11). Additional members grant access to some RPC
    calls, and Everyone in the group can extend that access to anonymous users when a system
    parameter lets Everyone include them.

    Anonymous Logon in the group is also reported here, as an additional member. It is the subject
    of the more severe test ANSSI-AD-039.

    The test looks at the direct members of the group: a nested membership is not followed. An
    empty group passes, since the test only forbids additional members.

    The test is skipped when the group is not in the collected data, or when its members cannot
    be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_compatible_2000_not_default.

    .EXAMPLE
    Test-MtAnssiAdPreWindows2000AdditionalMember

    Returns $true when the group has no member besides Authenticated Users, $false when it has,
    and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPreWindows2000AdditionalMember
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-056',
        Title = 'Pre-Windows 2000 Compatible Access should only include Authenticated Users',
        Product = 'ad',
        Feature = 'groups',
        Area = 'access-control',
        ResourceType = 'Group',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1087.002',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPreWindows2000AdditionalMember'

    $adState = Get-MtADDomainState -Categories @('Groups')

    $members = Get-MtAnssiAdGroupMemberDn -Group $adState.Groups -Sid 'S-1-5-32-554' `
        -ProtocolEvidence $adState.ProtocolEvidence

    if ($null -eq $members) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The Pre-Windows 2000 Compatible Access group (S-1-5-32-554) was not found in the ' +
            'collected data.')
        return $null
    }

    $extra = @(Get-MtAnssiAdPreWindows2000ExtraMember -Member $members.Member)
    Write-Verbose "Members: $($members.Member.Count), additional members: $($extra.Count)"

    if ($extra.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'The Pre-Windows 2000 Compatible Access group has no member besides ' +
            'Authenticated Users.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($extra | Sort-Object -Property DistinguishedName) `
        -Column ([ordered]@{
            'Identity' = { $_.Identity }
            'SID'      = { $_.Sid }
            'Member'   = { $_.DistinguishedName }
        })

    $result = "The Pre-Windows 2000 Compatible Access group has $($extra.Count) member(s) " +
        'besides Authenticated Users. They are granted access to some RPC calls, and Everyone ' +
        'in the group can give that access to anonymous users when a system parameter lets ' +
        "Everyone include them.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
