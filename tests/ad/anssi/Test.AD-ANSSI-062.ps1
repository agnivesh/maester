function Test-MtAnssiAdPrivilegedProtectedUserMembership {
    <#
    .SYNOPSIS
    ANSSI-AD-062: Privileged user accounts should be members of Protected Users.

    .DESCRIPTION
    Fails when an enabled privileged user account is not a member, directly, through nesting or
    through its primary group, of the domain's Protected Users group (RID 525). A privileged
    account is a member, direct, nested or through its primary group, of a group that Active
    Directory protects with AdminSDHolder, or the built-in Administrator or krbtgt account. When
    the Protected Users group does not exist, every enabled privileged user account is reported.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when the members of a group cannot be read.

    Corresponds to the ANSSI Active Directory checkpoint vuln_protected_users.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedProtectedUserMembership

    Returns $true when every enabled privileged user account is in Protected Users, $false when
    one is not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedProtectedUserMembership
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-062',
        Title = 'Privileged user accounts should be members of Protected Users',
        Product = 'ad',
        Feature = 'groups',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Medium',
        ImplementationCost = 'Low',
        Mitre = 'T1550.002',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedProtectedUserMembership'

    $adState = Get-MtADDomainState -Categories @('Domain', 'Users', 'Computers', 'Groups')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $protected = Get-MtAnssiAdGroupMemberAccount -AdState $adState -GroupSid "$domainSid-525"

    $users = @($privileged.Account |
        Where-Object { $_.Kind -eq 'User' -and $_.Item.Enabled -eq $true })
    $memberDn = $protected.MemberDn
    $findings = @($users | Where-Object { -not $memberDn.Contains($_.DistinguishedName) })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose ("Enabled privileged users: $($users.Count), outside Protected Users: " +
        "$($findings.Count)")

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($users.Count) enabled privileged user accounts " +
            "are members of Protected Users.$note")
        return $true
    }

    $missing = ''
    if ($null -eq $protected.Group) {
        $missing = ' The Protected Users group does not exist in this domain.'
    }
    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Item.SamAccountName }) `
        -Column ([ordered]@{
            'Account'            = { $_.Item.SamAccountName }
            'Privileged through' = { $_.Group -join ', ' }
            'Last logon'         = { Format-MtAnssiAdDate $_.Item.LastLogonDate }
        })

    $result = "$($findings.Count) of $($users.Count) enabled privileged user accounts are not " +
        "members of Protected Users.$missing$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
