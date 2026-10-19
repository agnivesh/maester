function Test-MtAnssiAdServerStalePassword45Day {
    <#
    .SYNOPSIS
    ANSSI-AD-060: Server passwords should be changed at least every 45 days.

    .DESCRIPTION
    Fails when the computer account of an enabled server has not changed its password for more
    than 45 days, or never did. Servers change their password automatically every 30 days by
    default. A server is a computer account whose operating system name contains Server and that
    is neither a domain controller nor a cluster account.

    The test is skipped when no enabled server computer account is in the collected data.

    .EXAMPLE
    Test-MtAnssiAdServerStalePassword45Day

    Returns $true when every enabled server changed its password within 45 days, $false when one
    did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdServerStalePassword45Day
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-060',
        Title = 'Server passwords should be changed at least every 45 days',
        Product = 'ad',
        Feature = 'computers',
        Area = 'identity-lifecycle',
        ResourceType = 'Computer',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdServerStalePassword45Day'

    $maxAgeDays = 45
    $now = (Get-Date).ToUniversalTime()

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $servers = (Get-MtAnssiAdServer -Computer $adState.Computers `
            -DomainController $adState.DomainControllers).Server
    $found = Get-MtAnssiAdStaleComputer -Computer @($servers) `
        -Attribute PasswordLastSet -Cutoff $now.AddDays(-$maxAgeDays) -NullIsStale
    $stale = @($found.Stale)
    Write-Verbose "Enabled: $($found.EnabledCount), stale password: $($stale.Count)"

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No enabled server computer account was found in the collected data.')
        return $null
    }

    if ($stale.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled servers changed their password within the " +
            "last $maxAgeDays days.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($stale | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Server'            = { $_.Computer.Name }
            'Operating system'  = { $_.Computer.OperatingSystem }
            'Password last set' = { Format-MtAnssiAdDate $_.Date }
            'Age in days'       = {
                if ($null -eq $_.Date) { 'n/a' } else { [int]($now - $_.Date).TotalDays }
            }
        })

    $result = "$($stale.Count) of $($found.EnabledCount) enabled servers have not changed " +
        "their password for more than $maxAgeDays days, which indicates their secrets are not " +
        "renewed. The cause must be investigated: it may be a sign of compromise.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
