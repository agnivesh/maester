function Test-MtAnssiAdDnsZoneInsecureUpdate {
    <#
    .SYNOPSIS
    ANSSI-AD-014: DNS zones should accept only secure dynamic updates.

    .DESCRIPTION
    Reads the DNS zones stored in Active Directory (in the domain naming context and in the
    DomainDnsZones and ForestDnsZones partitions) and fails when a zone accepts nonsecure dynamic
    updates, which let anyone on the network add or replace records without authenticating. The
    zone of the domain and the _msdcs zone of the forest are level 1 (Critical); any other zone is
    level 3 (Medium). The most severe level found is reported.

    The test is skipped when the domain name is not in the collected data, when a read fails, or
    when no DNS zone is visible (the account may lack read access, or DNS may not be stored in
    Active Directory).

    .EXAMPLE
    Test-MtAnssiAdDnsZoneInsecureUpdate

    Returns $true when no zone accepts nonsecure dynamic updates, $false when one does, and $null
    when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDnsZoneInsecureUpdate
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-014',
        Title = 'DNS zones should accept only secure dynamic updates',
        Product = 'ad',
        Feature = 'dns',
        Area = 'infrastructure',
        ResourceType = 'DnsZone',
        Severity = 'Critical',
        UserImpact = 'Medium',
        ImplementationCost = 'Medium',
        Mitre = 'T1557',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDnsZoneInsecureUpdate'

    $adState = Get-MtADDomainState -Categories @('Domain')

    $domain = $adState.Domain
    if (-not $domain.DistinguishedName -or -not $domain.DnsRoot -or -not $domain.Forest) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain or forest name was not found in the collected data.')
        return $null
    }

    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence)
    $base = @("CN=System,$($domain.DistinguishedName)") +
    @($head -match '^DC=(Domain|Forest)DnsZones,')
    $zones = @(Get-MtAnssiAdDnsZone -SearchBase $base `
        -ProtocolEvidence $adState.ProtocolEvidence)

    if ($zones.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No DNS zone stored in Active Directory is visible to the account that reads the ' +
            'directory. It may have no read access, or DNS may not be stored in Active Directory.')
        return $null
    }

    $findings = @(Get-MtAnssiAdDnsZoneFinding -Zone $zones -DnsRoot ([string]$domain.DnsRoot) `
            -Forest ([string]$domain.Forest))
    Write-Verbose "DNS zones: $($zones.Count), accepting nonsecure updates: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 3) -Result (
            "None of the $($zones.Count) DNS zones stored in Active Directory accepts nonsecure " +
            'dynamic updates.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Zone'               = { $_.Name }
            'Distinguished name' = { $_.DistinguishedName }
            'Severity'           = { Get-MtAnssiAdSeverity -Grade $_.Level }
        })
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) -Result (
        "$($findings.Count) of $($zones.Count) DNS zones accept nonsecure dynamic " +
        "updates.`n`n$table")
    return $false
}
