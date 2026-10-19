function Test-MtAnssiAdDisplaySpecifierScript {
    <#
    .SYNOPSIS
    ANSSI-AD-012: Display specifiers should not run programs from file servers outside SYSVOL.

    .DESCRIPTION
    Fails when a context menu entry of a display specifier (adminContextMenu or
    shellContextMenu) runs a program from a file share other than SYSVOL or NETLOGON. Display
    specifiers extend the menus of the Active Directory consoles for the whole forest, so whoever
    can change that program runs code as each administrator who uses the menu. Entries that run a
    program from SYSVOL or NETLOGON are listed but do not fail the test.

    The test is skipped when the display specifiers cannot be read or none is found.

    Corresponds to the ANSSI Active Directory checkpoint vuln_display_specifier.

    .EXAMPLE
    Test-MtAnssiAdDisplaySpecifierScript

    Returns $true when no display specifier runs a program from a file server outside SYSVOL,
    $false when one does, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDisplaySpecifierScript
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-012',
        Title = 'Display specifiers should not run programs from file servers outside SYSVOL',
        Product = 'ad',
        Feature = 'directory-configuration',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'High',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDisplaySpecifierScript'

    $adState = Get-MtADDomainState -Categories @('Domain')

    $specifiers = @(Get-MtAnssiAdDisplaySpecifier -ProtocolEvidence $adState.ProtocolEvidence)

    if ($specifiers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No display specifier was found in the Configuration partition.')
        return $null
    }

    $entries = @(Get-MtAnssiAdDisplaySpecifierScript -DisplaySpecifier $specifiers |
        Sort-Object -Property Location, Specifier, Command)
    $findings = @($entries | Where-Object { $_.Location -eq 'File server' })
    Write-Verbose ("Display specifiers: $($specifiers.Count), file server programs: " +
        "$($findings.Count)")
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $entries -Column ([ordered]@{
            'Display specifier' = { $_.Specifier }
            'Attribute'         = { $_.Attribute }
            'Program'           = { $_.Command }
            'Location'          = { $_.Location }
        })

    if ($findings.Count -eq 0) {
        $result = "None of the $($specifiers.Count) display specifiers runs a program from a " +
            'file server outside SYSVOL.'
        if ($entries.Count -gt 0) {
            $result += " $($entries.Count) context menu entries run one from SYSVOL or NETLOGON: " +
                "check that each one is still needed.`n`n$table"
        }
        Add-MtTestResultDetail -Result $result
        return $true
    }

    $result = "$($findings.Count) context menu entries of the display specifiers run a program " +
        'from a file server outside SYSVOL. Whoever can change those programs runs code as the ' +
        "administrators who use the menus.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
