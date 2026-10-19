function Test-MtAnssiAdDelegationToPrivilegedService {
    <#
    .SYNOPSIS
    ANSSI-AD-008: No account should have constrained delegation to a domain controller.

    .DESCRIPTION
    Fails when an enabled user or computer account has constrained delegation (Kerberos only)
    to a domain controller service or to the krbtgt service, in its msDS-AllowedToDelegateTo
    attribute. Such an account can obtain tickets to a domain controller on behalf of other
    users, which leads to the compromise of the domain.

    A service is privileged here when it runs on a domain controller or is the krbtgt service;
    other privileged servers are not recognized. Accounts that also have protocol transition are
    reported by ANSSI-AD-010.

    The test is skipped when no domain controller is found, or when the computers do not carry
    the delegation targets.

    Corresponds to the ANSSI Active Directory checkpoint vuln_delegation_a2d2.

    .EXAMPLE
    Test-MtAnssiAdDelegationToPrivilegedService

    Returns $true when no account has such a delegation, $false when one has, and $null when the
    test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDelegationToPrivilegedService
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-008',
        Title = 'No account should have constrained delegation to a domain controller',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDelegationToPrivilegedService'

    $delegation = 'constrained delegation'

    $adState = Get-MtADDomainState -Categories @('Users', 'Computers', 'DomainControllers')

    $computers = @($adState.Computers)
    $controllers = @(Get-MtAnssiAdDomainController -Computer $computers `
            -DomainController $adState.DomainControllers)
    $hasAttribute = $computers[0].PSObject.Properties.Name -contains 'AllowedToDelegateTo'
    if ($controllers.Count -eq 0 -or -not $hasAttribute) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller, or the delegation targets of the accounts, were found in the ' +
            'collected data.')
        return $null
    }

    $all = @(Get-MtAnssiAdPrivilegedDelegation -User $adState.Users -Computer $computers `
            -Controller $controllers)
    $findings = @($all | Where-Object { -not $_.ProtocolTransition })
    Write-Verbose "Accounts with $delegation to a privileged service: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "No enabled account has $delegation to a domain controller or to krbtgt.")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Account'            = { $_.Name }
            'Type'               = { $_.Kind }
            'Privileged targets' = { @($_.Target) -join ', ' }
        })

    $result = "$($findings.Count) enabled account(s) have $delegation to a domain controller " +
        'or to krbtgt. They can obtain tickets to a domain controller on behalf of other users ' +
        "and take over the domain.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
