function Get-MtAnssiAdDcCryptoFinding {
    <#
    .SYNOPSIS
    Finds the domain controllers that allow weak Kerberos encryption algorithms.

    .DESCRIPTION
    A domain controller publishes the algorithms it supports in msDS-SupportedEncryptionTypes. The
    rules and their ANSSI grades come from the checkpoint vuln_dc_crypto:

    - grade 2: DES-CBC-CRC (0x1) or DES-CBC-MD5 (0x2) is enabled, or the account is set to use DES
      keys only (userAccountControl USE_DES_KEY_ONLY, 0x200000);
    - grade 3: neither AES128 (0x8) nor AES256 (0x10) is enabled, which includes a controller that
      has no value;
    - grade 4: RC4 (0x4) is enabled.

    One object is returned for each controller that breaks at least one rule, with its worst grade
    and all its conditions, sorted by grade, then by name.

    .PARAMETER Controller
    The domain controllers, as returned by Get-MtAnssiAdDomainController.

    .EXAMPLE
    Get-MtAnssiAdDcCryptoFinding -Controller $controllers

    Returns the controllers with DES, without AES or with RC4, worst first.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [object[]] $Controller
    )

    $desKeyOnly = 0x200000
    $found = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $Controller) {
        $computer = $item.Computer
        $types = $computer.SupportedEncryptionTypes
        $value = 0
        $null = [int]::TryParse([string]$types, [ref]$value)

        $conditions = [System.Collections.Generic.List[object]]::new()
        if (($value -band 0x3) -ne 0 -or ($computer.UserAccountControl -band $desKeyOnly) -ne 0) {
            $conditions.Add(@{ Grade = 2; Text = 'DES enabled' })
        }
        if (($value -band 0x18) -eq 0) {
            $conditions.Add(@{ Grade = 3; Text = 'No AES128 or AES256' })
        }
        if (($value -band 0x4) -ne 0) {
            $conditions.Add(@{ Grade = 4; Text = 'RC4 enabled' })
        }
        if ($conditions.Count -eq 0) {
            continue
        }

        $found.Add([PSCustomObject]@{
                Name                     = $computer.Name
                DistinguishedName        = $computer.DistinguishedName
                Type                     = $item.Type
                SupportedEncryptionTypes = $types
                Grade                    = ($conditions | ForEach-Object { $_.Grade } |
                        Measure-Object -Minimum).Minimum
                Condition                = ($conditions | ForEach-Object { $_.Text }) -join ', '
            })
    }

    return @($found | Sort-Object -Property Grade, Name)
}
