function Test-MtAnssiAdDcInconsistentAttribute {
    <#
    .SYNOPSIS
    ANSSI-AD-006: Domain controller computer accounts should have consistent attributes.

    .DESCRIPTION
    Fails when a domain controller computer account does not have the attributes a domain
    controller has by default.

    A writable domain controller must have the SERVER_TRUST_ACCOUNT and TRUSTED_FOR_DELEGATION
    flags in userAccountControl and a domain controller entry of the configuration partition that
    points to its computer account. A read-only domain controller must have the
    PARTIAL_SECRETS_ACCOUNT, TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION and WORKSTATION_TRUST_ACCOUNT
    flags and no writable entry.

    The server object and NTDS Settings object of read-only domain controllers, and the
    msDS-Behavior-Version attribute, are not in the collected data and are not verified.

    The test is skipped when no domain controller computer account is in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dc_inconsistent_uac.

    .EXAMPLE
    Test-MtAnssiAdDcInconsistentAttribute

    Returns $true when every domain controller is consistent, $false when one is not, and $null
    when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcInconsistentAttribute
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-006',
        Title = 'Domain controller computer accounts should have consistent attributes',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'infrastructure',
        ResourceType = 'DomainController',
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

    Write-Verbose 'Starting Test-MtAnssiAdDcInconsistentAttribute'

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)

    if ($controllers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller computer account was found in the collected data.')
        return $null
    }

    $problems = @(Get-MtAnssiAdDcInconsistency -Controller $controllers)
    Write-Verbose "Inconsistencies: $($problems.Count)"

    if ($problems.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($controllers.Count) domain controller computer accounts have the expected " +
            'attributes.')
        return $true
    }

    $affected = @($problems | Select-Object -ExpandProperty Name -Unique).Count
    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($problems | Sort-Object -Property Name, Problem) `
        -Column ([ordered]@{
            'Domain controller' = { $_.Name }
            'Type'              = { $_.Type }
            'Problem'           = { $_.Problem }
        })

    $result = "$affected of $($controllers.Count) domain controller computer accounts have " +
        'inconsistent attributes. They can come from a manual or software-induced ' +
        "misconfiguration, or reveal malicious activity.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
