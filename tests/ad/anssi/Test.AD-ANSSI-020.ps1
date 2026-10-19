function Test-MtAnssiAdDcInactive {
    <#
    .SYNOPSIS
    ANSSI-AD-020: Domain controllers should authenticate at least every 45 days.

    .DESCRIPTION
    Fails when an enabled domain controller or read-only domain controller has not authenticated
    for more than 45 days, according to the lastLogonTimestamp of its computer account. The
    attribute is replicated with a delay of up to 14 days by default, which the 45 day limit
    absorbs. A controller without a value is not counted as inactive.

    The test is skipped when no enabled domain controller computer account is in the collected
    data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_password_change_inactive_dc.

    .EXAMPLE
    Test-MtAnssiAdDcInactive

    Returns $true when every enabled domain controller authenticated within 45 days, $false when
    one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcInactive
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-020',
        Title = 'Domain controllers should authenticate at least every 45 days',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'identity-lifecycle',
        ResourceType = 'DomainController',
        Severity = 'Low',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDcInactive'

    $maxAgeDays = 45
    $now = (Get-Date).ToUniversalTime()

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)
    $typeByComputer = @{}
    $computers = foreach ($controller in $controllers) {
        $typeByComputer[[string]$controller.Computer.DistinguishedName] = $controller.Type
        $controller.Computer
    }
    $found = Get-MtAnssiAdStaleComputer -Computer @($computers) `
        -Attribute LastLogonDate -Cutoff $now.AddDays(-$maxAgeDays)
    $inactive = @($found.Stale)
    Write-Verbose "Enabled: $($found.EnabledCount), inactive: $($inactive.Count)"

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No enabled domain controller computer account was found in the collected data.')
        return $null
    }

    if ($inactive.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled domain controllers authenticated within the " +
            "last $maxAgeDays days.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($inactive | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Domain controller' = { $_.Computer.Name }
            'Type'              = { $typeByComputer[[string]$_.Computer.DistinguishedName] }
            'Last logon'        = { Format-MtAnssiAdDate $_.Date }
            'Age in days'       = { [int]($now - $_.Date).TotalDays }
        })

    $result = "$($inactive.Count) of $($found.EnabledCount) enabled domain controllers have not " +
        "authenticated for more than $maxAgeDays days. Domain controllers must authenticate and " +
        "change their password at least every 30 days: a lack of authentication reveals an " +
        "out-of-sync machine.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
