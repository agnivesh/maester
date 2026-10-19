function Test-MtAnssiAdDcObsoleteOperatingSystem {
    <#
    .SYNOPSIS
    ANSSI-AD-007: Domain controllers should not run an obsolete operating system.

    .DESCRIPTION
    Fails when a domain controller or read-only domain controller runs a Windows version whose
    extended support has ended, so that Microsoft no longer publishes security updates for it.

    The end of support dates come from the Microsoft Lifecycle pages and are compared with the
    current date, so a version is reported from the day after its end date. A domain controller
    whose operating system is empty or is not a known Windows version is listed in the result but
    does not fail the test.

    The test is skipped when no domain controller computer account is in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dc_obsolete.

    .EXAMPLE
    Test-MtAnssiAdDcObsoleteOperatingSystem

    Returns $true when no domain controller runs an obsolete operating system, $false when one
    does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcObsoleteOperatingSystem
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-007',
        Title = 'Domain controllers should not run an obsolete operating system',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'infrastructure',
        ResourceType = 'DomainController',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'T1210',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDcObsoleteOperatingSystem'

    $today = (Get-Date).ToUniversalTime().Date

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)

    if ($controllers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller computer account was found in the collected data.')
        return $null
    }

    $classified = Get-MtAnssiAdObsoleteDomainController -Controller $controllers -Today $today
    $obsolete = @($classified.Obsolete)
    $unknownCount = $classified.UnknownCount
    Write-Verbose "Obsolete: $($obsolete.Count), unknown operating system: $unknownCount"

    $unknownNote = ''
    if ($unknownCount -gt 0) {
        $unknownNote = "`n`n$unknownCount domain controller(s) have an empty or unrecognized " +
            'operating system and were not evaluated.'
    }

    if ($obsolete.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "None of the $($controllers.Count) domain controllers runs an obsolete operating " +
            "system.$unknownNote")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($obsolete | Sort-Object -Property EndOfSupport, Name) `
        -Column ([ordered]@{
            'Domain controller' = { $_.Name }
            'Type'              = { $_.Type }
            'Operating system'  = { $_.OperatingSystem }
            'Support ended'     = { Format-MtAnssiAdDate $_.EndOfSupport }
        })

    $result = "$($obsolete.Count) of $($controllers.Count) domain controllers run an operating " +
        'system for which Microsoft no longer publishes security updates. Any new vulnerability ' +
        "found in these systems stays exploitable.$unknownNote`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
