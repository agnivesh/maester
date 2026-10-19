function Test-MtAnssiAdClusterStalePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-047: Cluster account passwords should be changed at least every 3 years.

    .DESCRIPTION
    Fails when the password of an enabled Windows server cluster computer account was last set more
    than 3 years ago, or never. A cluster account is a computer account with a service principal
    name that starts with MSClusterVirtualServer/: the cluster name account and the accounts of
    clustered services and applications carry it.

    The test is skipped when no enabled cluster account is in the collected data.

    .EXAMPLE
    Test-MtAnssiAdClusterStalePassword

    Returns $true when every enabled cluster account changed its password within 3 years, $false
    when one did not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdClusterStalePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-047',
        Title = 'Cluster account passwords should be changed at least every 3 years',
        Product = 'ad',
        Feature = 'computers',
        Area = 'identity-lifecycle',
        ResourceType = 'Computer',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdClusterStalePassword'

    $now = (Get-Date).ToUniversalTime()

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $clusters = (Get-MtAnssiAdServer -Computer $adState.Computers `
            -DomainController $adState.DomainControllers).Cluster
    $found = Get-MtAnssiAdStaleComputer -Computer @($clusters) `
        -Attribute PasswordLastSet -Cutoff $now.AddYears(-3) -NullIsStale
    $stale = @($found.Stale)
    Write-Verbose "Enabled: $($found.EnabledCount), stale password: $($stale.Count)"

    if ($found.EnabledCount -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No enabled cluster computer account was found in the collected data.')
        return $null
    }

    if ($stale.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($found.EnabledCount) enabled cluster accounts changed their password within " +
            'the last 3 years.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($stale | Sort-Object -Property Date, { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Cluster account'   = { $_.Computer.Name }
            'Password last set' = { Format-MtAnssiAdDate $_.Date }
            'Age in days'       = {
                if ($null -eq $_.Date) { 'n/a' } else { [int]($now - $_.Date).TotalDays }
            }
        })

    $result = "$($stale.Count) of $($found.EnabledCount) enabled cluster accounts have not " +
        'changed their password for more than 3 years, which indicates their secrets are not ' +
        "renewed.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
