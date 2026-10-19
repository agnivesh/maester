function Test-MtAnssiAdDcResourceDelegation {
    <#
    .SYNOPSIS
    ANSSI-AD-009: No domain controller should allow resource-based constrained delegation.

    .DESCRIPTION
    Fails when the computer account of a domain controller or read-only domain controller has the
    msDS-AllowedToActOnBehalfOfOtherIdentity attribute. The accounts it allows can obtain tickets
    to the domain controller on behalf of any user, which leads to the compromise of the domain.

    The attribute is reported whatever it holds, since resource-based delegation should not be
    configured on a domain controller at all. Only the computer accounts of the domain controllers
    are evaluated.

    The test is skipped when no domain controller computer account is found, or when the
    computers do not carry the attribute.

    Corresponds to the ANSSI Active Directory checkpoint vuln_delegation_sourcedeleg.

    .EXAMPLE
    Test-MtAnssiAdDcResourceDelegation

    Returns $true when no domain controller allows resource-based delegation, $false when one
    does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcResourceDelegation
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-009',
        Title = 'No domain controller should allow resource-based constrained delegation',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'privileged-access',
        ResourceType = 'DomainController',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDcResourceDelegation'

    $adState = Get-MtADDomainState -Categories @(
        'Users', 'Computers', 'Groups', 'DomainControllers')

    $computers = @($adState.Computers)
    $controllers = @(Get-MtAnssiAdDomainController -Computer $computers `
            -DomainController $adState.DomainControllers)
    $property = 'AllowedToActOnBehalfOfOtherIdentity'
    $hasAttribute = $computers[0].PSObject.Properties.Name -contains $property
    if ($controllers.Count -eq 0 -or -not $hasAttribute) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller computer account, or its resource-based delegation attribute, ' +
            'was found in the collected data.')
        return $null
    }

    $lookup = Get-MtAnssiAdSidByDn -User $adState.Users -Computer $computers `
        -Group $adState.Groups
    $findings = @(Get-MtAnssiAdDcResourceDelegation -Controller $controllers -Lookup $lookup)
    Write-Verbose "Domain controllers with resource-based delegation: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "None of the $($controllers.Count) domain controllers allows resource-based " +
            'constrained delegation.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Domain controller' = { $_.Name }
            'Type'              = { $_.Type }
            'Allowed accounts'  = { @($_.Allowed) -join ', ' }
        })

    $result = "$($findings.Count) of $($controllers.Count) domain controllers allow " +
        'resource-based constrained delegation. The accounts they allow can obtain tickets to ' +
        "the domain controller on behalf of any user and take over the domain.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
