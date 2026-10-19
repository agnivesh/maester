function Get-MtAnssiAdPkiContainerRule {
    <#
    .SYNOPSIS
    Returns the rights that let a principal take over a certificate container or CA object.

    .DESCRIPTION
    ANSSI says that dangerous permissions on the certificate containers allow an attacker to add a
    malicious certification authority. The rows, in matching order and in the form of the rows of
    Get-MtAnssiAdAceRule, are full control, the right to change permissions or owner, writing all
    attributes, writing the cACertificate attribute (the list of CAs that a container or the
    NTAuthCertificates store trusts) and creating child objects (adding a CA). ANSSI gives this
    finding level 1 only, so every row is level 1. Reading, enrolling and the other rights are not
    listed.

    .EXAMPLE
    Get-MtAnssiAdPkiContainerRule

    Returns the rows to give to Get-MtAnssiAdAceControl.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $caCertificate = 'bf967932-0de6-11d0-a285-00aa003049e2'
    $table = @(
        , @('GenericAll', 0x10000000, '*')
        , @('GenericAll', 0xF01FF, '*')
        , @('WriteDacl', 0x40000, '*')
        , @('WriteOwner', 0x80000, '*')
        , @('GenericWrite', 0x40000000, '*')
        , @('GenericWrite', 0x20, '')
        , @('WriteCaCertificate', 0x20, $caCertificate)
        , @('CreateChild', 0x1, '*')
    )
    foreach ($row in $table) {
        [PSCustomObject]@{
            Control = $row[0]; Level = 1; Mask = [uint32]$row[1]; ObjectType = $row[2]
            Class = $null; IgnoreType = $null
        }
    }
}
