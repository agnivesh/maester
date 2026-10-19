function Get-MtAnssiAdEnrollmentRight {
    <#
    .SYNOPSIS
    Lists the principals outside the trusted set that can enroll in certificate templates.

    .DESCRIPTION
    Goes through the DACL of each template and keeps the allow entries that give an untrusted
    principal the right to enroll: the Certificate-Enrollment extended right, all extended rights,
    or full control. Autoenrollment, reading, and the rights to change the template (which
    Get-MtAnssiAdAceControl reports for ANSSI-AD-002) do not count, and the owner is not reported.
    Inherit-only entries are skipped and an earlier deny entry cancels a right, as for the other
    permission tests. Returns one row per entry with DistinguishedName, Name, Sid, Control and
    IsInherited. Throws for a template whose DACL was not read, because its rights are unknown.

    .PARAMETER Object
    The template objects, as returned by Get-MtLdapObjectSecurity.

    .PARAMETER TrustedSid
    The SIDs whose rights are expected, for example from Get-MtAnssiAdTrustedSid.

    .EXAMPLE
    Get-MtAnssiAdEnrollmentRight -Object $templates -TrustedSid $trusted

    Returns the enrollment rights held by untrusted principals.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Object,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $TrustedSid
    )

    $enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $table = @(
        , @('GenericAll', 0x10000000, '*')
        , @('GenericAll', 0xF01FF, '*')
        , @('Enroll', 0x100, $enroll)
        , @('AllExtendedRights', 0x100, '')
    )
    $rule = foreach ($row in $table) {
        [PSCustomObject]@{
            Control = $row[0]; Level = 1; Mask = [uint32]$row[1]; ObjectType = $row[2]
            Class = $null; IgnoreType = $null
        }
    }
    $ruleBit = [uint32]0x10000100

    $allSid = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Object) {
        if ($null -eq $item.Ace) {
            throw "The DACL of '$($item.DistinguishedName)' was not read: its rights are unknown."
        }
        foreach ($ace in $item.Ace) { $null = $allSid.Add([string]$ace.Sid) }
    }
    $untrusted = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(Select-MtAnssiAdUntrustedSid -Sid @($allSid) -TrustedSid $TrustedSid),
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in $Object) {
        Get-MtAnssiAdObjectAceControl -Object $item -UntrustedSid $untrusted -Rule $rule `
            -RuleBit $ruleBit
    }
}
