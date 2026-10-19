function Get-MtAnssiAdPkiContainerAssessment {
    <#
    .SYNOPSIS
    Lists who outside the trusted set controls the PKI containers and CA objects of the forest.

    .DESCRIPTION
    Reads, once per session, the owner and permissions of the objects below CN=Public Key
    Services in the Configuration partition: the containers, the certification authority objects
    (including the NTAuthCertificates store), the enrollment services, the CRL distribution points
    and the key recovery agents. The certificate templates are left to ANSSI-AD-002. Rights come
    from Get-MtAnssiAdPkiContainerRule. Besides the trusted set, a default CA installation is
    expected: the Cert Publishers group of the domain (RID 517) and the computer accounts of the CA
    servers (Get-MtAnssiAdCaHostSid) hold full control of their own objects. Returns the number of
    objects read (ObjectCount) and the findings (Finding). Throws when a read fails or the
    permissions of an object cannot be read.

    .PARAMETER AdState
    The collected state, with Domain, Computers and ProtocolEvidence.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected, for example from Get-MtAnssiAdTrustedSid. Not changed.

    .EXAMPLE
    Get-MtAnssiAdPkiContainerAssessment -AdState $adState -TrustedSid $trusted

    Returns the objects counted and the rights held by untrusted principals.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [object] $AdState,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid
    )

    $evidence = $AdState.ProtocolEvidence
    $head = @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $evidence)
    $configuration = @($head -like 'CN=Configuration,*')[0]
    $classes = 'container', 'certificationAuthority', 'pKIEnrollmentService',
    'cRLDistributionPoint', 'msPKI-PrivateKeyRecoveryAgent'
    $filter = '(|' + (($classes | ForEach-Object { "(objectClass=$_)" }) -join '') + ')'
    $objects = @(Get-MtAnssiAdSearchSecurity `
            -SearchBase "CN=Public Key Services,CN=Services,$configuration" -Scope Subtree `
            -Filter $filter -Attribute @('dNSHostName') -ProtocolEvidence $evidence)

    $expected = [System.Collections.Generic.HashSet[string]]::new($TrustedSid,
        [System.StringComparer]::OrdinalIgnoreCase)
    $null = $expected.Add("$($AdState.Domain.DomainSID.Value)-517")
    $service = @($objects | Where-Object { @($_.ObjectClass) -contains 'pKIEnrollmentService' })
    $caHost = @(Get-MtAnssiAdCaHostSid -EnrollmentService $service -Computer $AdState.Computers)
    foreach ($sid in $caHost) { $null = $expected.Add($sid) }
    return [PSCustomObject]@{
        ObjectCount = $objects.Count
        Finding     = @(Get-MtAnssiAdAceControl -Object $objects -TrustedSid $expected `
                -Rule @(Get-MtAnssiAdPkiContainerRule))
    }
}
