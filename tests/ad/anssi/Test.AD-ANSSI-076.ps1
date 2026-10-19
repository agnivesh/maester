function Test-MtAnssiAdDomainMachineAccountQuota {
    <#
    .SYNOPSIS
    ANSSI-AD-076: Authenticated users should not be able to join computers to the domain.

    .DESCRIPTION
    Fails when the ms-DS-MachineAccountQuota attribute of the domain root is not 0. By default
    any authenticated user may join up to 10 computers to the domain. When the attribute is not
    set the default of 10 applies.

    Corresponds to the ANSSI Active Directory checkpoint vuln_user_accounts_machineaccountquota.

    .EXAMPLE
    Test-MtAnssiAdDomainMachineAccountQuota

    Returns $true when the quota is 0, $false when it is not, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDomainMachineAccountQuota
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-076',
        Title = 'Authenticated users should not be able to join computers to the domain',
        Product = 'ad',
        Feature = 'domain-and-forest',
        Area = 'access-control',
        ResourceType = 'Tenant',
        Severity = 'Low',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDomainMachineAccountQuota'

    $defaultQuota = 10

    $adState = Get-MtADDomainState -Categories @('Domain')

    if ($null -eq $adState.Domain) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain object was not found in the collected data.')
        return $null
    }

    $quota = $adState.Domain.MsDsMachineAccountQuota
    $note = ''
    if ($null -eq $quota) {
        $quota = $defaultQuota
        $note = ' (the attribute is not set, so the default applies)'
    }
    Write-Verbose "ms-DS-MachineAccountQuota: $quota"

    if ($quota -eq 0) {
        $summary = 'ms-DS-MachineAccountQuota is 0: authenticated users cannot join computers ' +
            'to the domain.'
        Add-MtTestResultDetail -Result $summary
        return $true
    }

    $result = "ms-DS-MachineAccountQuota is $quota$($note): any authenticated user can join up " +
        "to $quota computers to the domain. The computer accounts created this way are owned " +
        "by the account that created them, which gives it full control over them."

    Add-MtTestResultDetail -Result $result
    return $false
}
