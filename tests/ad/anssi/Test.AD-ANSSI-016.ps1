function Test-MtAnssiAdDsHeuristicsDangerousValue {
    <#
    .SYNOPSIS
    ANSSI-AD-016: The dSHeuristics attribute should not hold dangerous settings.

    .DESCRIPTION
    Reports the dangerous settings in the dSHeuristics attribute of the directory service. The
    severity is decided at run time, so this test has no severity in the Maester configuration.
    It is the severity of the most severe ANSSI grade among the settings found:
    - grade 1, Critical: fAllowAnonNSPI or dwAdminSDExMask is not 0.
    - grade 2, High: fLDAPBlockAnonOps is 2, DoNotVerifyUPNAndOrSPNUniqueness or
      DisableConfidentialAttributeEncryptionRequirements is not 0, or
      AttributeAuthorizationOnLDAPAdd or BlockOwnerImplicitRights is 2.
    - grade 4, Low: AttributeAuthorizationOnLDAPAdd or BlockOwnerImplicitRights is not explicitly 1.

    A passing test reports the most severe possible severity.

    The test is skipped when the directory configuration is not in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dsheuristics_bad.

    .EXAMPLE
    Test-MtAnssiAdDsHeuristicsDangerousValue

    Returns $true when dSHeuristics holds no dangerous setting, $false when it does, and $null when
    the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDsHeuristicsDangerousValue
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-016',
        Title = 'The dSHeuristics attribute should not hold dangerous settings',
        Product = 'ad',
        Feature = 'directory-configuration',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'Critical',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDsHeuristicsDangerousValue'

    $mostSevere = Get-MtAnssiAdSeverity -Grade 1, 2, 4

    $adState = Get-MtADDomainState -Categories @('Configuration')

    if ($null -eq $adState.Configuration) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The directory configuration was not found in the collected data.')
        return $null
    }

    $dsHeuristics = $adState.Configuration.DsHeuristics
    $findings = @(Get-MtAnssiAdDsHeuristicsFinding -DsHeuristics $dsHeuristics)
    Write-Verbose "Dangerous dSHeuristics settings: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity $mostSevere -Result (
            'The dSHeuristics attribute holds no dangerous setting.')
        return $true
    }

    $severity = Get-MtAnssiAdSeverity -Grade @($findings | ForEach-Object { $_.Grade })
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Setting'           = { $_.Setting }
            'Position'          = { $_.Position }
            'Value'             = { $_.Value }
            'Recommended value' = { $_.Recommended }
            'Severity'          = { Get-MtAnssiAdSeverity -Grade $_.Grade }
        })

    $current = 'not set'
    if (-not [string]::IsNullOrEmpty($dsHeuristics)) { $current = Get-MtSafeMarkdown $dsHeuristics }

    $result = "Found $($findings.Count) dangerous dSHeuristics setting(s). The current value of " +
        "the attribute is $current.`n`n$table"

    Add-MtTestResultDetail -Result $result -Severity $severity
    return $false
}
