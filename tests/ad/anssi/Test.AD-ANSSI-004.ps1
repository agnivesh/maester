function Test-MtAnssiAdPkiWeakCertificate {
    <#
    .SYNOPSIS
    ANSSI-AD-004: CA certificates in Active Directory should use strong keys and signatures.

    .DESCRIPTION
    Reads the certificates that Active Directory publishes to the forest (the cACertificate
    values below the Services container of the Configuration partition: certification
    authorities, AIA objects, the NTAuth store and enrollment services) and fails when one has a
    weak key or signature. A DSA key, an RSA key under 1024 bits or with the ROCA weakness is
    level 1 (Critical); a certificate that cannot be parsed is level 2 (High); an RSA key under
    2048 bits, a public exponent under 65537 or a signature hash other than SHA-2 or SHA-3 is
    level 3 (Medium). Expired certificates are judged too. The most severe level found is
    reported.

    The test is skipped when a read fails.

    .EXAMPLE
    Test-MtAnssiAdPkiWeakCertificate

    Returns $true when no certificate is weak, $false when one is, and $null when the test is
    skipped.

    .LINK
    https://maester.dev/docs/commands/Test-MtAnssiAdPkiWeakCertificate
    #>
    [MaesterTest(
        Id = 'AD-ANSSI-004',
        Title = 'CA certificates in Active Directory should use strong keys and signatures',
        Product = 'ad',
        Feature = 'certificate-services',
        Area = 'infrastructure',
        ResourceType = 'CertificateAuthority',
        Severity = 'Medium',
        UserImpact = 'Low',
        ImplementationCost = 'High',
        Mitre = 'None',
        Service = 'ActiveDirectory',
        Author = 'agnivesh'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Verbose 'Starting Test-MtAnssiAdPkiWeakCertificate'

    $adState = Get-MtADDomainState -Categories @('Domain')

    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $adState.ProtocolEvidence)
    $configuration = @($head -like 'CN=Configuration,*')[0]
    $objects = @(Get-MtAnssiAdCaCertificate -SearchBase "CN=Services,$configuration" `
            -ProtocolEvidence $adState.ProtocolEvidence)

    $count = 0
    foreach ($item in $objects) { $count += @($item.Certificate).Count }
    $findings = @(Get-MtAnssiAdCertificateFinding -Object $objects)
    Write-Verbose "Certificates: $count, weak: $($findings.Count)"

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade 1, 2, 3) -Result (
            "None of the $count certificates stored in Active Directory has a weak key or " +
            'signature.')
        return $true
    }

    $table = ConvertTo-MtAnssiAdMarkdownTable -InputObject $findings -Column ([ordered]@{
            'Object'      = { $_.DistinguishedName }
            'Subject'     = { $_.Subject }
            'Valid until' = { Format-MtAnssiAdDate -Date $_.NotAfter -NullText 'Unknown' }
            'Problems'    = { $_.Problem -join '; ' }
            'Severity'    = { Get-MtAnssiAdSeverity -Grade $_.Level }
        })
    Add-MtTestResultDetail -Severity (Get-MtAnssiAdSeverity -Grade @($findings.Level)) -Result (
        "$($findings.Count) of the $count certificates stored in Active Directory have a weak " +
        "key or signature.`n`n$table")
    return $false
}
