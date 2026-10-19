function Test-MtAnssiAdPrimaryGroupBelow1000 {
    <#
    .SYNOPSIS
    ANSSI-AD-031: No account should have a primary group below 1000 other than its default.

    .DESCRIPTION
    Fails when a user or computer account has a primaryGroupID lower than 1000 that is not the
    default of its type. Group IDs below 1000 are the built-in groups of the domain, such as
    Domain Admins (512), and are usually privileged. The primary group gives an implicit
    membership that does not appear in the member list of the group, so it can hide a privileged
    membership.

    Defaults: users 513 or 514, computers 515, writable domain controllers 516, read-only domain
    controllers 521. Disabled accounts are evaluated too: the hidden membership applies as soon
    as the account is enabled. A group ID of 1000 or more that differs from the default is
    reported by ANSSI-AD-061.

    The test is skipped when the users and computers were not collected, or when no account has
    a primary group ID in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_primary_group_id_1000.

    .EXAMPLE
    Test-MtAnssiAdPrimaryGroupBelow1000

    Returns $true when no account has a non-default primary group below 1000, $false when one
    has, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrimaryGroupBelow1000
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-031',
        Title = 'No account should have a non-default primary group below 1000',
        Product = 'ad',
        Feature = 'groups',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrimaryGroupBelow1000'

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers')

    $assessed = @(Get-MtAnssiAdPrimaryGroupAssessment -User $adState.Users `
            -Computer $adState.Computers)

    if ($assessed.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No user or computer account with a primary group ID was found in the collected data.')
        return $null
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($account in $assessed) {
        if ($account.IsDeviation -and $account.PrimaryGroupId -lt 1000) {
            $findings.Add($account)
        }
    }
    Write-Verbose "Accounts checked: $($assessed.Count), findings: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "None of the $($assessed.Count) user and computer accounts has a primary group below " +
            '1000 other than the default of its type.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property PrimaryGroupId, Name) `
        -Column ([ordered]@{
            'Account'          = { $_.Name }
            'Type'             = { $_.Type }
            'Enabled'          = { $_.Enabled }
            'Primary group ID' = { $_.PrimaryGroupId }
            'Expected'         = { $_.Expected }
        })

    $result = "$($findings.Count) of $($assessed.Count) user and computer accounts have a " +
        'primary group below 1000 that is not the default of their type. Such a group is usually ' +
        'privileged, and the membership through the primary group does not appear in the ' +
        "member list of the group.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
