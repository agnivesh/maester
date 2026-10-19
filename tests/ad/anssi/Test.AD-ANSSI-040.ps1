function Test-MtAnssiAdDcEncryptionType {
    <#
    .SYNOPSIS
    ANSSI-AD-040: Domain controllers should only support AES for Kerberos.

    .DESCRIPTION
    Fails when a domain controller or read-only domain controller supports a weak Kerberos
    encryption algorithm in msDS-SupportedEncryptionTypes. The severity depends on what is found:
    High for DES (DES-CBC-CRC or DES-CBC-MD5), Medium when neither AES128 nor AES256 is enabled
    (a controller without a value counts here), Low for RC4. The result carries the most severe
    level found.

    The attribute is the one the controller publishes about itself; it follows the "Network
    security: Configure encryption types allowed for Kerberos" setting once the controller has
    restarted. The test does not read the setting or the encryption types the controllers
    actually use.

    The test is skipped when no domain controller computer account is in the collected data, or
    when the computers do not carry the attribute.

    Corresponds to the ANSSI Active Directory checkpoint vuln_dc_crypto.

    .EXAMPLE
    Test-MtAnssiAdDcEncryptionType

    Returns $true when every domain controller only supports AES, $false when one supports DES,
    no AES or RC4, and $null when the test is skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdDcEncryptionType
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-040',
        Title = 'Domain controllers should only support AES for Kerberos',
        Product = 'ad',
        Feature = 'domain-controllers',
        Area = 'authentication',
        ResourceType = 'DomainController',
        Severity = 'High',
        UserImpact = 'Medium',
        ImplementationCost = 'Medium',
        Mitre = 'T1558',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdDcEncryptionType'

    $mostSevere = Get-MtAnssiAdSeverity -Grade 2, 3, 4

    $adState = Get-MtADDomainState -Categories @('Computers', 'DomainControllers')

    $controllers = @(Get-MtAnssiAdDomainController -Computer $adState.Computers `
            -DomainController $adState.DomainControllers)

    if ($controllers.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'No domain controller computer account was found in the collected data.')
        return $null
    }

    if ($controllers[0].Computer.PSObject.Properties.Name -notcontains 'SupportedEncryptionTypes') {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason (
            'The msDS-SupportedEncryptionTypes attribute of the computers was not found in the ' +
            'collected data.')
        return $null
    }

    $findings = @(Get-MtAnssiAdDcCryptoFinding -Controller $controllers)
    Write-Verbose "Domain controllers: $($controllers.Count), with a finding: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity $mostSevere -Result (
            "All $($controllers.Count) domain controllers only support AES for Kerberos.")
        return $true
    }

    $severity = Get-MtAnssiAdSeverity -Grade @($findings | ForEach-Object { $_.Grade })
    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Domain controller' = { $_.Name }
            'Type'              = { $_.Type }
            'Encryption types'  = {
                ConvertTo-MtAnssiAdEncryptionTypeText $_.SupportedEncryptionTypes
            }
            'Findings'          = { $_.Condition }
            'Severity'          = { Get-MtAnssiAdSeverity -Grade $_.Grade }
        })

    $result = "$($findings.Count) of $($controllers.Count) domain controllers support a weak " +
        'Kerberos encryption algorithm. DES is obsolete, a controller without AES cannot use ' +
        "modern tickets, and RC4 weakens the passwords it protects.`n`n$table"

    Add-MtTestResultDetail -Result $result -Severity $severity
    return $false
}
