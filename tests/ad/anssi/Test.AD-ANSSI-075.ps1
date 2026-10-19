function Test-MtAnssiAdDomainSmartCardPasswordExpiration {
    <#
    .SYNOPSIS
    ANSSI-AD-075: Passwords of smart card only accounts should expire.

    .DESCRIPTION
    Fails when the attribute msDS-ExpirePasswordsOnSmartCardOnlyAccounts is not TRUE on the root
    of the domain. Without it, the password hash of an account that requires a smart card is set
    once and never rotates, so a stolen hash stays valid for as long as the account exists.

    The attribute is only effective at the Windows Server 2016 domain functional level. The test
    is skipped below it, because the attribute cannot take effect there; ANSSI-AD-017 reports
    the functional level.

    The test is skipped when the domain or its functional level is not in the collected data.

    Corresponds to the ANSSI Active Directory checkpoint vuln_smartcard_expire_passwords.

    .EXAMPLE
    Test-MtAnssiAdDomainSmartCardPasswordExpiration

    Returns $true when the attribute is TRUE, $false when it is FALSE or not set, and $null when
    the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDomainSmartCardPasswordExpiration
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-075',
        Title = 'Passwords of smart card only accounts should expire',
        Product = 'ad',
        Feature = 'password-policy',
        Area = 'identity-lifecycle',
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

    Write-Verbose 'Starting Test-MtAnssiAdDomainSmartCardPasswordExpiration'

    $adState = Get-MtADDomainState -Categories @('Domain')

    $domain = $adState.Domain
    $level = ConvertTo-MtAnssiAdFunctionalLevel -Mode $domain.DomainMode

    if ($null -eq $level) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The domain and its functional level were not found in the collected data.')
        return $null
    }

    if ($level -lt 7) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            "The domain functional level is $level, below Windows Server 2016 (level 7), the " +
            'level from which the attribute takes effect. See ANSSI-AD-017.')
        return $null
    }

    $value = $domain.ExpirePasswordsOnSmartCardOnlyAccounts
    Write-Verbose "msDS-ExpirePasswordsOnSmartCardOnlyAccounts: $value"

    $isBoolean = $value -is [bool]
    if ($isBoolean -and $value) {
        Add-MtTestResultDetail -Result (
            "The attribute msDS-ExpirePasswordsOnSmartCardOnlyAccounts is TRUE on $($domain.Name).")
        return $true
    }

    $state = 'is not set'
    if ($isBoolean) {
        $state = 'is FALSE'
    }

    Add-MtTestResultDetail -Result (
        "The attribute msDS-ExpirePasswordsOnSmartCardOnlyAccounts $state on the root of the " +
        "domain $($domain.Name). The passwords of accounts that require a smart card are not " +
        'rotated automatically.')
    return $false
}
