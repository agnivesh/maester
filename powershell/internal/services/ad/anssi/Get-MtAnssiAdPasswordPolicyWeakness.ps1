function Get-MtAnssiAdPasswordPolicyWeakness {
    <#
    .SYNOPSIS
    Lists what makes a password policy weak for a privileged account.

    .DESCRIPTION
    Following ANSSI, a policy is weak when its minimum password length is under 8 characters, or
    when passwords never have to change or may stay unchanged for more than 3 years (3 x 365
    days). A maximum age that is not set or is 0 means that passwords never expire.

    .PARAMETER MinLength
    The minimum password length of the policy.

    .PARAMETER MaxAge
    The maximum password age of the policy, as a timespan; $null or zero means never.

    .EXAMPLE
    Get-MtAnssiAdPasswordPolicyWeakness -MinLength 7 -MaxAge $null

    Returns 'minimum length 7' and 'passwords never expire'.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object] $MinLength,

        [AllowNull()]
        [Nullable[timespan]] $MaxAge
    )

    $weakness = [System.Collections.Generic.List[string]]::new()
    if ([int]$MinLength -lt 8) {
        $weakness.Add("minimum length $([int]$MinLength)")
    }
    if ($null -eq $MaxAge -or $MaxAge -eq [timespan]::Zero) {
        $weakness.Add('passwords never expire')
    } elseif ($MaxAge -gt [timespan]::FromDays(3 * 365)) {
        $weakness.Add("maximum age $([int]$MaxAge.TotalDays) days")
    }

    return $weakness.ToArray()
}
