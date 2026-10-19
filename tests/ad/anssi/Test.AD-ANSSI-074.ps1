function Test-MtAnssiAdPrivilegedAuthenticationSilo {
    <#
    .SYNOPSIS
    ANSSI-AD-074: Privileged accounts should be in an enforced authentication policy silo.

    .DESCRIPTION
    Fails when an enabled account that is a member, directly, through nesting or through its
    primary group, of a group Active Directory protects with AdminSDHolder is not assigned to an
    authentication policy silo, is assigned to a silo that is not enforced, or is assigned to a
    silo that does not grant it access. The built-in Administrator account, which authentication
    policies never apply to, and the domain controller accounts are not checked.

    The test is skipped when the domain SID is not in the collected data, when a protected group
    is missing, or when a read fails.

    Corresponds to the ANSSI Active Directory checkpoint vuln_silo_priv.

    .EXAMPLE
    Test-MtAnssiAdPrivilegedAuthenticationSilo

    Returns $true when every checked privileged account is in an enforced silo, $false when one
    is not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPrivilegedAuthenticationSilo
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-074',
        Title = 'Privileged accounts should be in an enforced authentication policy silo',
        Product = 'ad',
        Feature = 'account-security',
        Area = 'privileged-access',
        ResourceType = 'User',
        Severity = 'Low',
        UserImpact = 'Low',
        ImplementationCost = 'Medium',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPrivilegedAuthenticationSilo'

    $adState = Get-MtADDomainState -Categories @(
        'Domain', 'Users', 'Computers', 'Groups', 'DomainControllers')

    $domainSid = [string]$adState.Domain.DomainSID.Value
    if (-not $domainSid) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain SID was not found in the collected data.')
        return $null
    }

    $privileged = Get-MtAnssiAdPrivilegedAccount -User $adState.Users `
        -Computer $adState.Computers -Group $adState.Groups -DomainSid $domainSid `
        -ProtocolEvidence $adState.ProtocolEvidence
    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)
    $accounts = @(Select-MtAnssiAdCountedPrivilegedAccount -Account $privileged.Account `
            -DomainController $controllers -DomainSid $domainSid |
        Where-Object { $_.Item.Enabled -eq $true })
    $status = @(Get-MtAnssiAdSiloAssignment -Account $accounts `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $findings = @($status | Where-Object { $_.Problem })
    $note = Format-MtAnssiAdUnresolvedNote -Unresolved $privileged.Unresolved
    Write-Verbose ("Privileged accounts checked: $($accounts.Count), outside a silo: " +
        "$($findings.Count)")

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result ("All $($accounts.Count) checked privileged accounts are " +
            "in an enforced authentication policy silo.$note")
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property { $_.Account.Item.SamAccountName }) `
        -DomainSource { $_.Account.DistinguishedName } `
        -Column ([ordered]@{
            'Account'            = { $_.Account.Item.SamAccountName }
            'Type'               = { $_.Account.Kind }
            'Silo'               = { $_.Silo }
            'Problem'            = { $_.Problem }
            'Privileged through' = { $_.Account.Group -join ', ' }
        })

    $result = "$($findings.Count) of $($accounts.Count) checked privileged accounts are not " +
        "properly in an enforced authentication policy silo.$note`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
