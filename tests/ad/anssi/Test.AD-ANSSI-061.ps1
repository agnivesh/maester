function Test-MtAnssiAdPrimaryGroupModified {
    <#
    .SYNOPSIS
    ANSSI-AD-061: No account should have a modified primary group.

    .DESCRIPTION
    Fails when a user or computer account has a primaryGroupID that is not the default of its
    type. The primary group gives an implicit membership that does not appear in the member list
    of the group in some interfaces, so a modified value can hide a group membership.

    Defaults: users 513 or 514, computers 515, writable domain controllers 516, read-only domain
    controllers 521. Disabled accounts are evaluated too: the hidden membership applies as soon
    as the account is enabled. The test reports every modified value; the accounts whose value
    is below 1000, usually a privileged group, are also reported by the more severe test
    ANSSI-AD-031.

    The test is skipped when the users and computers were not collected, or when no account has
    a primary group ID in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_primary_group_id_nochange.

    .EXAMPLE
    Test-MtAnssiAdPrimaryGroupModified

    Returns $true when every account has the default primary group of its type, $false when one
    has not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrimaryGroupModified
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-061',
        Title = 'No account should have a modified primary group',
        Product = 'ad',
        Feature = 'groups',
        Area = 'access-control',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrimaryGroupModified'

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
        if ($account.IsDeviation) {
            $findings.Add($account)
        }
    }
    Write-Verbose "Accounts checked: $($assessed.Count), findings: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($assessed.Count) user and computer accounts have the default primary group of " +
            'their type.')
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
        'primary group that is not the default of their type. The membership through the ' +
        'primary group does not appear in the member list of the group in some interfaces, so ' +
        "it can hide a group membership.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
