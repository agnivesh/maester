function Get-MtAnssiAdDsHeuristicsFinding {
    <#
    .SYNOPSIS
    Finds the dangerous settings in a dSHeuristics value.

    .DESCRIPTION
    dSHeuristics is a string in which each character is a setting at a fixed position (MS-ADTS
    6.1.1.2.4.1.2). A character that is missing because the string is shorter has the default 0.
    For AttributeAuthorizationOnLDAPAdd and BlockOwnerImplicitRights the effective value is used:
    a character other than 0 to 3 counts as 1.

    The rules and their ANSSI grades come from the checkpoint vuln_dsheuristics_bad. A setting that
    breaks several rules is returned once, with the most severe grade. The result is sorted by
    grade, then by position.

    .PARAMETER DsHeuristics
    The dSHeuristics value. A null or empty value means every setting has its default.

    .EXAMPLE
    Get-MtAnssiAdDsHeuristicsFinding -DsHeuristics '0000002'

    Returns fLDAPBlockAnonOps (grade 2) and the two settings that are not explicitly 1 (grade 4).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $DsHeuristics
    )

    $rules = @(
        @{ Setting = 'fAllowAnonNSPI'; Position = 8; Grade = 1; MustEqual = $false; Value = '0' }
        @{ Setting = 'dwAdminSDExMask'; Position = 16; Grade = 1; MustEqual = $false; Value = '0' }
        @{ Setting = 'fLDAPBlockAnonOps'; Position = 7; Grade = 2; MustEqual = $true; Value = '2' }
        @{ Setting = 'DoNotVerifyUPNAndOrSPNUniqueness'; Position = 21; Grade = 2
            MustEqual = $false; Value = '0' }
        @{ Setting = 'AttributeAuthorizationOnLDAPAdd'; Position = 28; Grade = 2
            MustEqual = $true; Value = '2'; Effective = $true }
        @{ Setting = 'BlockOwnerImplicitRights'; Position = 29; Grade = 2
            MustEqual = $true; Value = '2'; Effective = $true }
        @{ Setting = 'DisableConfidentialAttributeEncryptionRequirements'; Position = 31; Grade = 2
            MustEqual = $false; Value = '0' }
        @{ Setting = 'AttributeAuthorizationOnLDAPAdd'; Position = 28; Grade = 4
            MustEqual = $false; Value = '1'; Effective = $true }
        @{ Setting = 'BlockOwnerImplicitRights'; Position = 29; Grade = 4
            MustEqual = $false; Value = '1'; Effective = $true }
    )

    # Padding with the default 0 gives every missing character its default value.
    $text = [string]$DsHeuristics
    $padded = $text.PadRight(31, '0')
    $findings = foreach ($rule in $rules) {
        $character = [string]$padded[$rule.Position - 1]
        $effective = $character
        if ($rule.Effective -and $character -notin '0', '1', '2', '3') { $effective = '1' }

        if (($effective -eq $rule.Value) -eq $rule.MustEqual) {
            $recommended = $rule.Value
            if ($rule.MustEqual) { $recommended = "not $($rule.Value)" }
            $shown = 'not set'
            if ($rule.Position -le $text.Length) { $shown = $character }
            [PSCustomObject]@{
                Setting     = $rule.Setting
                Position    = $rule.Position
                Value       = $shown
                Recommended = $recommended
                Grade       = $rule.Grade
            }
        }
    }

    return @($findings | Group-Object -Property Setting |
            ForEach-Object { $_.Group | Sort-Object -Property Grade | Select-Object -First 1 } |
            Sort-Object -Property Grade, Position)
}
