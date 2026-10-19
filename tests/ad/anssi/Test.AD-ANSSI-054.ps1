function Test-MtAnssiAdSysvolNtfrsReplication {
    <#
    .SYNOPSIS
    ANSSI-AD-054: SYSVOL should be replicated with DFS Replication instead of NTFRS.

    .DESCRIPTION
    Fails when a domain controller or read-only domain controller has no SYSVOL subscription of
    the DFS Replication service. Such a controller does not replicate the SYSVOL share with DFS
    Replication: it still uses the obsolete File Replication Service (NTFRS), or its replication
    is broken.

    The test sees the subscriptions that exist, not the migration state of the domain. While a
    domain is being migrated (Prepared or Redirected state), the subscriptions exist although
    NTFRS still replicates SYSVOL, so the test can pass before the migration is complete.

    The test is skipped when no domain controller computer account is in the collected data, or
    when the DFS Replication subscriptions were not collected.

    Corresponds to the ANSSI Active Directory checkpoint vuln_sysvol_ntfrs.

    .EXAMPLE
    Test-MtAnssiAdSysvolNtfrsReplication

    Returns $true when every domain controller has a SYSVOL subscription, $false when one has
    not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdSysvolNtfrsReplication
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-054',
        Title = 'SYSVOL should be replicated with DFS Replication instead of NTFRS',
        Product = 'ad',
        Feature = 'replication',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdSysvolNtfrsReplication'

    $adState = Get-MtADDomainState -Categories @(
        'Computers', 'DomainControllers', 'DfsrSubscriptions')

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)

    if ($controllers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller computer account was found in the collected data.')
        return $null
    }

    if ($null -eq $adState.DfsrSubscriptions) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The DFS Replication subscriptions were not found in the collected data.')
        return $null
    }

    $missing = @(Get-MtAnssiAdControllerWithoutSysvolDfsr -Controller $controllers `
            -Subscription $adState.DfsrSubscriptions)
    Write-Verbose "Controllers without a SYSVOL subscription: $($missing.Count)"

    if ($missing.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($controllers.Count) domain controllers have a SYSVOL DFS Replication " +
            'subscription.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($missing | Sort-Object -Property { $_.Computer.Name }) `
        -DomainSource { $_.Computer.DistinguishedName } `
        -Column ([ordered]@{
            'Domain controller' = { $_.Computer.Name }
            'Type'              = { $_.Type }
            'Operating system'  = { $_.Computer.OperatingSystem }
        })

    $result = "$($missing.Count) of $($controllers.Count) domain controllers have no SYSVOL " +
        'DFS Replication subscription, so they do not replicate SYSVOL with DFS Replication. ' +
        'They use the obsolete File Replication Service (NTFRS), which exposes unnecessary ' +
        "administration interfaces and is not supported by recent Windows Server versions, or " +
        "their replication is broken.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
