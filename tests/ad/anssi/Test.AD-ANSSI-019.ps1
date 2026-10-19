function Test-MtAnssiAdDcStalePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-019: Domain controller passwords should be changed at least every 45 days.

    .DESCRIPTION
    Fails when the computer account of an enabled domain controller or read-only domain controller
    has not changed its password for more than 45 days, or never did. Domain controllers change
    their password automatically every 30 days by default.

    The test is skipped when no enabled domain controller computer account is in the collected
    data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_password_change_dc_no_change.

    .EXAMPLE
    Test-MtAnssiAdDcStalePassword

    Returns $true when every enabled domain controller changed its password within 45 days, $false
    when one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcStalePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-019',
        Title = 'Domain controller passwords should be changed at least every 45 days',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'infrastructure',
        ResourceType = 'DomainController',
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

    Write-Verbose 'Starting Test-MtAnssiAdDcStalePassword'

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
        -Attribute PasswordLastSet -Cutoff $now.AddDays(-$maxAgeDays) -NullIsStale
    $stale = @($found.Stale)
    Write-Verbose "Enabled: $($found.EnabledCount), stale password: $($stale.Count)"

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No enabled domain controller computer account was found in the collected data.')
        return $null
    }

    if ($stale.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled domain controllers changed their " +
            "password within the last $maxAgeDays days.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($stale | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Domain controller' = { $_.Computer.Name }
            'Type'              = { $typeByComputer[[string]$_.Computer.DistinguishedName] }
            'Password last set' = { Format-MtAnssiAdDate $_.Date }
            'Age in days'       = {
                if ($null -eq $_.Date) { 'n/a' } else { [int]($now - $_.Date).TotalDays }
            }
        })

    $result = "$($stale.Count) of $($found.EnabledCount) enabled domain controller computer " +
        "accounts have not changed their password for more than $maxAgeDays days, which " +
        "indicates their secrets are not renewed. The cause must be investigated: it may be " +
        "a sign of compromise.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
