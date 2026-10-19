function Select-MtAnssiAdUntrustedSid {
    <#
    .SYNOPSIS
    Returns the SIDs that are not trusted for the ANSSI permission checks.

    .DESCRIPTION
    A SID is trusted when it is in TrustedSid, or when it is the group with RID 498, 518, 519 or
    527 of any domain: these are forest-wide groups of the forest root domain, whose SID a child
    domain cannot compute, and adprep also wrote a domain-relative 527 entry in child domains
    (Microsoft Learn, domain-wide updates of Windows Server 2016). Empty values are dropped.

    .PARAMETER Sid
    The SIDs to check.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected.

    .EXAMPLE
    Select-MtAnssiAdUntrustedSid -Sid @('S-1-5-18', 'S-1-5-21-1-2-3-1105') -TrustedSid $trusted

    Returns S-1-5-21-1-2-3-1105 when only S-1-5-18 is in the trusted set.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]] $Sid,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid
    )

    foreach ($value in $Sid) {
        if ([string]::IsNullOrEmpty($value) -or $TrustedSid.Contains($value)) {
            continue
        }
        if ($value -notmatch '^S-1-5-21-\d+-\d+-\d+-(498|518|519|527)$') {
            $value
        }
    }
}
