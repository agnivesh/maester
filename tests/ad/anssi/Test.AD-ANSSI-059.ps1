function Test-MtAnssiAdServerInactive {
    <#
    .SYNOPSIS
    ANSSI-AD-059: Servers should authenticate at least every 90 days.

    .DESCRIPTION
    Fails when an enabled server has not authenticated for more than 90 days, according to the
    lastLogonTimestamp of its computer account. The attribute is replicated with a delay of up to
    14 days by default, which the limit absorbs. A server without a value is not counted as
    inactive. A server is a computer account whose operating system name contains Server and that
    is neither a domain controller nor a cluster account.

    The test is skipped when no enabled server computer account is in the collected data.

    .EXAMPLE
    Test-MtAnssiAdServerInactive

    Returns $true when every enabled server authenticated within 90 days, $false when one did not,
    and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdServerInactive
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-059',
        Title = 'Servers should authenticate at least every 90 days',
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

    Write-Verbose 'Starting Test-MtAnssiAdServerInactive'

    $maxAgeDays = 90
    $now = (Get-Date).ToUniversalTime()

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $servers = (Get-MtAnssiAdServer -Computer $adState.Computers `
            -DomainController $adState.DomainControllers).Server
    $found = Get-MtAnssiAdStaleComputer -Computer @($servers) `
        -Attribute LastLogonDate -Cutoff $now.AddDays(-$maxAgeDays)
    $inactive = @($found.Stale)
    Write-Verbose "Enabled: $($found.EnabledCount), inactive: $($inactive.Count)"

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No enabled server computer account was found in the collected data.')
        return $null
    }

    if ($inactive.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled servers authenticated within the last " +
            "$maxAgeDays days.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($inactive | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Server'           = { $_.Computer.Name }
            'Operating system' = { $_.Computer.OperatingSystem }
            'Last logon'       = { Format-MtAnssiAdDate $_.Date }
            'Age in days'      = { [int]($now - $_.Date).TotalDays }
        })

    $result = "$($inactive.Count) of $($found.EnabledCount) enabled servers have not " +
        "authenticated for more than $maxAgeDays days. Servers must authenticate and change " +
        "their password at least every 30 days: a lack of authentication reveals an " +
        "out-of-sync machine.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
