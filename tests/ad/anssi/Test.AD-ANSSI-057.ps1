function Test-MtAnssiAdServiceAccountEncryptionType {
    <#
    .SYNOPSIS
    ANSSI-AD-057: Service accounts should declare support for Kerberos AES encryption.

    .DESCRIPTION
    Fails when an enabled user account with a servicePrincipalName does not declare AES128 or
    AES256 in msDS-SupportedEncryptionTypes, because the attribute is not set or has neither AES
    bit. The domain controllers use the attribute to choose the encryption of the tickets issued
    to the service; an account without it falls back to the default of the domain controllers,
    which depends on their patch level and on the DefaultDomainSupportedEncTypes registry value
    and can be RC4. ANSSI asks for an explicit value, for example 28 (0x1C).

    Computer accounts are not evaluated: Windows computers set the attribute themselves. Group
    managed and managed service accounts are computer-class objects and are not evaluated either.

    The test is skipped when the users were not collected or when the collected users do not
    carry the attribute.

    Corresponds to the ANSSI Active Directory checkpoint vuln_kerberos_properties_encryption.

    .EXAMPLE
    Test-MtAnssiAdServiceAccountEncryptionType

    Returns $true when every enabled service account declares AES, $false when one does not, and
    $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdServiceAccountEncryptionType
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-057',
        Title = 'Service accounts should declare support for Kerberos AES encryption',
        Product = 'ad',
        Feature = 'service-principal-names',
        Area = 'authentication',
        ResourceType = 'User',
        Severity = 'Medium',
        UserImpact = 'Medium',
        ImplementationCost = 'Medium',
        Mitre = 'T1558.003',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdServiceAccountEncryptionType'

    $adState = Get-MtADDomainState -Categories @('Users')

    $users = @($adState.Users)
    if ($users[0].PSObject.Properties.Name -notcontains 'SupportedEncryptionTypes') {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The users or their msDS-SupportedEncryptionTypes attribute were not found in the ' +
            'collected data.')
        return $null
    }

    $serviceAccounts = @(Get-MtAnssiAdServiceAccount -User $users)
    $findings = @($serviceAccounts | Where-Object { -not $_.SupportsAes })
    Write-Verbose "Service accounts: $($serviceAccounts.Count), without AES: $($findings.Count)"

    if ($serviceAccounts.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            'No enabled user account has a service principal name.')
        return $true
    }

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result (
            "All $($serviceAccounts.Count) enabled user accounts with a service principal name " +
            'declare support for Kerberos AES encryption.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable `
        -InputObject @($findings | Sort-Object -Property Name) `
        -Column ([ordered]@{
            'Account'                = { $_.Name }
            'Service principal name' = { $_.ServicePrincipalName }
            'Encryption types'       = {
                ConvertTo-MtAnssiAdEncryptionTypeText $_.SupportedEncryptionTypes
            }
            'Last logon'             = { Format-MtAnssiAdDate $_.LastLogonDate }
        })

    $result = "$($findings.Count) of $($serviceAccounts.Count) enabled user accounts with a " +
        'service principal name do not declare support for Kerberos AES encryption. The tickets ' +
        'issued to their services may use a weaker algorithm such as RC4, which exposes the ' +
        "account to offline password cracking.`n`n$table"

    Add-MtTestResultDetail -Result $result
    return $false
}
