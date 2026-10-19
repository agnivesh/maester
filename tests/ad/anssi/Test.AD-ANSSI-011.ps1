function Test-MtAnssiAdUnconstrainedDelegation {
    <#
    .SYNOPSIS
    ANSSI-AD-011: Only domain controllers should be trusted for unconstrained delegation.

    .DESCRIPTION
    Fails when an enabled user or computer account that is not a domain controller has the
    TRUSTED_FOR_DELEGATION flag in userAccountControl. An account trusted for unconstrained
    delegation can act as any user that authenticates to it. By default, only domain controllers
    have it.

    The test is skipped when no user or computer account is in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_delegation_t4d.

    .EXAMPLE
    Test-MtAnssiAdUnconstrainedDelegation

    Returns $true when no account other than a domain controller is trusted for unconstrained
    delegation, $false when one is, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdUnconstrainedDelegation
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-011',
        Title = 'Only domain controllers should be trusted for unconstrained delegation',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdUnconstrainedDelegation'

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers', 'DomainControllers')

    $missing = Get-MtAnssiAdMissingDataReason -State $adState `
        -Name 'Users', 'Computers', 'DomainControllers'
    if ($missing) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $missing
        return $null
    }

    if (@($adState.Users).Count + @($adState.Computers).Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No user or computer account was found in the collected data.')
        return $null
    }

    $accounts = @(Get-MtAnssiAdUnconstrainedAccount -User $adState.Users `
            -Computer $adState.Computers -DomainController $adState.DomainControllers)

    if ($accounts.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'No enabled account other than a domain controller is trusted for unconstrained ' +
            'delegation.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($accounts | Sort-Object -Property Type, Name) `
        -Column ([ordered]@{
            'Type'             = { $_.Type }
            'Account'          = { $_.Name }
            'Operating system' = { $_.OperatingSystem }
            'Last logon'       = { Format-MtAnssiAdDate $_.LastLogonDate }
        })

    $result = "$($accounts.Count) enabled accounts that are not domain controllers are trusted " +
        'for unconstrained delegation. Such an account can act as any user that authenticates ' +
        "to it, which lets it elevate privileges and compromise the forest.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
