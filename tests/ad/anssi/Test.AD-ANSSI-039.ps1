function Test-MtAnssiAdPreWindows2000AnonymousAccess {
    <#
    .SYNOPSIS
    ANSSI-AD-039: The Pre-Windows 2000 Compatible Access group should not include Anonymous Logon.

    .DESCRIPTION
    Fails when the built-in group Pre-Windows 2000 Compatible Access (S-1-5-32-554) has the
    Anonymous Logon identity (S-1-5-7) as a member. This membership allows anonymous access to
    some of the content of Active Directory on the domain controllers.

    The test looks at the direct members of the group. Anonymous Logon is a foreign security
    principal, so a nested membership through another group is not detected. Other additional
    members of the group are not evaluated by this test.

    The test is skipped when the group is not in the collected data, or when its members cannot
    be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_compatible_2000_anonymous.

    .EXAMPLE
    Test-MtAnssiAdPreWindows2000AnonymousAccess

    Returns $true when Anonymous Logon is not a member, $false when it is, and $null when the
    test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPreWindows2000AnonymousAccess
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-039',
        Title = 'Pre-Windows 2000 Compatible Access should not include Anonymous Logon',
        Product = 'ad',
        Feature = 'groups',
        Area = 'access-control',
        ResourceType = 'Group',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1087.002',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPreWindows2000AnonymousAccess'

    $adState = Get-MtADDomainState -Categories @('Groups')

    $members = Get-MtAnssiAdGroupMemberDn -Group $adState.Groups -Sid 'S-1-5-32-554' `
        -ProtocolEvidence $adState.ProtocolEvidence

    if ($null -eq $members) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The Pre-Windows 2000 Compatible Access group (S-1-5-32-554) was not found in the ' +
            'collected data.')
        return $null
    }

    $memberDn = $members.Member
    $anonymous = @($memberDn | Where-Object {
            [string]$_ -imatch '^CN=S-1-5-7,CN=ForeignSecurityPrincipals,'
        })
    Write-Verbose "Members: $($memberDn.Count), Anonymous Logon entries: $($anonymous.Count)"

    if ($anonymous.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'The Pre-Windows 2000 Compatible Access group does not include Anonymous Logon.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject @($anonymous) `
        -Column ([ordered]@{ 'Member of Pre-Windows 2000 Compatible Access' = { $_ } })

    $result = 'The Pre-Windows 2000 Compatible Access group includes Anonymous Logon ' +
        '(S-1-5-7), which allows anonymous access to some of the content of Active Directory ' +
        "on the domain controllers.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
