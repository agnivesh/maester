function Get-MtAnssiAdCaHostSid {
    <#
    .SYNOPSIS
    Returns the SIDs of the computers that host the enterprise CAs.

    .DESCRIPTION
    An enterprise CA installation gives the computer account of the CA server full control of its
    own objects in the PKI containers. The enrollment service of each CA names its server in the
    dNSHostName attribute. Returns the SID of each collected computer with that DNS host name. A
    CA server of a domain other than the collected one is not among the computers, so it is not
    returned. Names are compared without regard to case.

    .PARAMETER EnrollmentService
    The enrollment service objects, with dNSHostName in their Attribute dictionary.

    .PARAMETER Computer
    The collected computers, with DnsHostName and Sid.

    .EXAMPLE
    Get-MtAnssiAdCaHostSid -EnrollmentService $services -Computer $adState.Computers

    Returns the SIDs of the CA servers.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $EnrollmentService,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Computer
    )

    $hostName = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($service in $EnrollmentService) {
        $name = [string]$service.Attribute['dNSHostName']
        if ($name) { $null = $hostName.Add($name) }
    }

    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Computer) {
        $sid = [string]$item.Sid.Value
        $isHost = $hostName.Contains([string]$item.DnsHostName)
        if ($sid -and $isHost) { $found.Add($sid) }
    }
    return $found.ToArray()
}
