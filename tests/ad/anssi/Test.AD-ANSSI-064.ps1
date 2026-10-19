function Test-MtAnssiAdDomainReversiblePassword {
    <#
    .SYNOPSIS
    ANSSI-AD-064: Domain passwords should not be stored with reversible encryption.

    .DESCRIPTION
    Fails when the pwdProperties attribute at the root of the domain has the
    DOMAIN_PASSWORD_STORE_CLEARTEXT flag (value 16). With this flag, every password changed after
    the flag was set is stored with reversible encryption, so that it can be recovered from a copy
    of the directory.

    The test is skipped when the domain object or its pwdProperties attribute is not in the
    collected data, because an unknown value is not a safe one.

    Corresponds to the ANSSI Active Directory checkpoint
    vuln_reversible_password_priv_namingcontext.

    .EXAMPLE
    Test-MtAnssiAdDomainReversiblePassword

    Returns $true when the flag is not set, $false when it is, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDomainReversiblePassword
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-064',
        Title = 'Domain passwords should not be stored with reversible encryption',
        Product = 'ad',
        Feature = 'password-policy',
        Area = 'infrastructure',
        ResourceType = 'Tenant',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'Low',
        Mitre = 'T1003.006',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDomainReversiblePassword'

    $storeCleartext = 16

    $adState = Get-MtADDomainState -Categories @('Domain')

    if ($null -eq $adState.Domain.PwdProperties) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The pwdProperties attribute of the domain was not found in the collected data.')
        return $null
    }

    $properties = $adState.Domain.PwdProperties
    Write-Verbose "pwdProperties: $properties"

    if (($properties -band $storeCleartext) -eq 0) {
        Add-MtTestResultDetail -Result (
            "The pwdProperties attribute of the domain is $($properties): it does not have the " +
            'DOMAIN_PASSWORD_STORE_CLEARTEXT flag (16).')
        return $true
    }

    $result = "The pwdProperties attribute of the domain is $properties and has the " +
        'DOMAIN_PASSWORD_STORE_CLEARTEXT flag (16). Every password changed since the flag was ' +
        'set is stored with reversible encryption and can be recovered from a copy of the ' +
        'directory. The passwords stay recoverable until they are changed.'

    Add-MtTestResultDetail -Result $result
    return $false
}
