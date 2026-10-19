function Test-MtAnssiAdFunctionalLevel {
    <#
    .SYNOPSIS
    ANSSI-AD-017: The forest functional level should be at least Windows Server 2016.

    .DESCRIPTION
    Rates the forest functional level against the thresholds of the ANSSI checkpoint
    vuln_functional_level. The severity is decided at run time, so this test has no severity in
    the Maester configuration:
    - below Windows Server 2008 R2 (level 4): ANSSI grade 1, Critical
    - below Windows Server 2012 R2 (level 6): ANSSI grade 3, Medium
    - below Windows Server 2016 (level 7): ANSSI grade 4, Low

    A passing test reports the most severe possible severity.

    The test is skipped when the forest functional level is not in the collected data.

    .EXAMPLE
    Test-MtAnssiAdFunctionalLevel

    Returns $true when the forest functional level is Windows Server 2016 or later, $false when it
    is lower, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdFunctionalLevel
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-017',
        Title = 'The forest functional level should be at least Windows Server 2016',
        Product = 'ad',
        Feature = 'domain-and-forest',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdFunctionalLevel'

    $thresholds = @(
        @{ Below = 4; Grade = 1 }
        @{ Below = 6; Grade = 3 }
        @{ Below = 7; Grade = 4 }
    )
    $levelNames = @(
        'Windows 2000', 'Windows Server 2003 interim', 'Windows Server 2003', 'Windows Server 2008',
        'Windows Server 2008 R2', 'Windows Server 2012', 'Windows Server 2012 R2',
        'Windows Server 2016 or later'
    )

    $adState = Get-MtADDomainState -Categories @('Forest', 'Domain')

    $forestLevel = ConvertTo-MtAnssiAdFunctionalLevel -Mode $adState.Forest.ForestMode
    if ($null -eq $forestLevel) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The forest functional level was not found in the collected data.')
        return $null
    }

    $forestName = $levelNames[[Math]::Min($forestLevel, 7)]
    $matching = $thresholds | Where-Object { $forestLevel -lt $_.Below } | Select-Object -First 1
    $grade = $matching.Grade
    Write-Verbose "Forest functional level: $forestLevel, ANSSI grade: $grade"

    if ($null -eq $grade) {
        $mostSevere = Get-MtAnssiAdSeverity -Grade @($thresholds | ForEach-Object { $_.Grade })
        Add-MtTestResultDetail -Severity $mostSevere -Result (
            "The forest functional level is $forestName (level $forestLevel).")
        return $true
    }

    $severity = Get-MtAnssiAdSeverity -Grade $grade
    $row = [PSCustomObject]@{ Name = $forestName; Level = $forestLevel; Severity = $severity }
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject @($row) -Column ([ordered]@{
            'Scope'            = { 'Forest' }
            'Functional level' = { $_.Name }
            'Level'            = { $_.Level }
            'Severity'         = { $_.Severity }
        })

    $domainNote = ''
    $domainLevel = ConvertTo-MtAnssiAdFunctionalLevel -Mode $adState.Domain.DomainMode
    if ($null -ne $domainLevel) {
        $domainName = $levelNames[[Math]::Min($domainLevel, 7)]
        $domainNote = " The functional level of the domain is $domainName (level $domainLevel)."
    }

    $result = "The forest functional level is $forestName (level $forestLevel), below Windows " +
        "Server 2016 (level 7). A low functional level deprives the forest of important " +
        "security features.$domainNote`n`n$table"

    Add-MtTestResultDetail -Result $result -Severity $severity
    return $false
}
