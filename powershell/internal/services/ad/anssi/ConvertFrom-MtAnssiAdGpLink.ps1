function ConvertFrom-MtAnssiAdGpLink {
    <#
    .SYNOPSIS
    Splits a gPLink value into its group policy links.

    .DESCRIPTION
    A gPLink value is a sequence of [LDAP://<GPO distinguished name>;<options>] entries. Returns
    one object per entry with the GPO distinguished name and the Disabled (option bit 0x1) and
    Enforced (option bit 0x2) flags (Microsoft Learn, Group Policy scope). An empty value gives
    nothing; text that is not a link entry is ignored. An option number of any length is read.

    .PARAMETER Value
    The gPLink value.

    .EXAMPLE
    ConvertFrom-MtAnssiAdGpLink -Value '[LDAP://cn={1},cn=policies,cn=system,DC=x;2]'

    Returns the link to cn={1},cn=policies,cn=system,DC=x, enforced and enabled.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    $pattern = '\[LDAP://([^;\]]+);(\d+)\]'
    foreach ($match in [regex]::Matches([string]$Value, $pattern, 'IgnoreCase')) {
        # The options are a decimal number of any length. Its two lowest bits depend only on
        # the last two digits, because 100 is divisible by 4.
        $digits = $match.Groups[2].Value
        $options = [int]$digits.Substring([Math]::Max(0, $digits.Length - 2))
        [PSCustomObject]@{
            Gpo      = $match.Groups[1].Value
            Disabled = [bool]($options -band 1)
            Enforced = [bool]($options -band 2)
        }
    }
}
