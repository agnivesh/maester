BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A certificate from the ROCA authors' test data (crocs-muni/roca, MIT licence): a
    # self-signed certificate with an RSA 2050-bit key from the vulnerable library.
    $script:certificate = [Convert]::FromBase64String(
            'MIICpTCCAYwCCQC2u0PIfFaGMjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTcx' +
            'MDE2MTkzODIxWhcNMTgxMDE2MTkzODIxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB' +
            'AQUAA4IBDwAwggEKAoIBAQJZJ7UrpeaMjJJou5IY83ZzYUymVBj0dFsUPNTuU/lJHJoOHC8jqVFjBq/784Zn' +
            'uHG8DMguYPW7Gp+hWlZxp2XJ8huVh9gBFZZDcqODyIOw3L9sd1cGsx6v8+P9SIVZoIzeog+al8TFm2uKjuyk' +
            'V9SoINSVCfdZM2MCvKGjaQsICRgR+Fjy6M6lpiNVrW4EHRk17aWSibWXaDtz4mV650v/x2Dk1RPMh9uTVZGO' +
            'qgjTmLvl9oNdyHElIRubNrOgvHC5k6bLP30stAYd5z25cslCrfmVW2/kzZDwDQiK7ASvH17/kfIa9e1EYXx9' +
            'uAk/lTZtsmWAxK85neuU+bFBMFvhAgMBAAEwDQYJKoZIhvcNAQELBQADggECAAG7W49CYRUkYAFRGXu3M85M' +
            'KOISyc/kkJ8nbHdV6GxJ05FkoDKbcbZ7nncJiIp2VMAMEIP4bRTJ5U4g4vSZlmCs8BDmV3Ts/tbDCM6eqK+2' +
            'hwjhUnCnmmsLt4xVUeAAsWUHl9AVtjzdoYlm1Kk20QBzNpsvM/gFS5B+duHvTSfELfoq9Pdfvmn2gEXJHe9s' +
            'cO8bfT3fm15zR6AUYsSsxAhup2Rix6jgJ14KGsh6uVm6jhz9aBTBcgx7iMuuP8zUbUE6nryHYXnRcSvuYSes' +
            'TCoFfnL7elrZDak/n0jLfwUD80aWnReJfu9QQGdqdDnSG8lSQ1XPOC7O/hFW9l0TCzOE'
    )

    # Fixed seed: every run feeds the parsers the same damaged inputs, so a failure can be
    # reproduced from the bytes the message shows.
    $script:state = [long]20261006

    function Get-NextNumber {
        param([int] $Limit)
        $script:state = (($script:state * 1664525) + 1013904223) -band 0xFFFFFFFFL
        [int](($script:state -shr 16) % $Limit)
    }

    function Get-SidFixture {
        param([int[]] $SubAuthority)
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.AddRange([byte[]](1, $SubAuthority.Count, 0, 0, 0, 0, 0, 5))
        foreach ($value in $SubAuthority) {
            $bytes.AddRange([BitConverter]::GetBytes([uint32]$value))
        }
        , $bytes.ToArray()
    }

    function Get-AceFixture {
        param([int] $Type, [int] $Flags, [uint32] $Mask, [byte[]] $Sid, [int] $ObjectFlags = 0)
        $body = [System.Collections.Generic.List[byte]]::new()
        $body.AddRange([BitConverter]::GetBytes($Mask))
        if ($Type -in 5, 6) {
            $body.AddRange([BitConverter]::GetBytes([uint32]$ObjectFlags))
            if ($ObjectFlags -band 1) { $body.AddRange([byte[]](1..16)) }
            if ($ObjectFlags -band 2) { $body.AddRange([byte[]](17..32)) }
        }
        $body.AddRange($Sid)
        $ace = [System.Collections.Generic.List[byte]]::new()
        $ace.Add([byte]$Type)
        $ace.Add([byte]$Flags)
        $ace.AddRange([BitConverter]::GetBytes([uint16](4 + $body.Count)))
        $ace.AddRange($body)
        , $ace.ToArray()
    }

    # A self-relative descriptor with an owner and a DACL of five entries: basic allow, object
    # allow with both GUIDs, basic deny, object deny with one GUID, and an unknown type.
    function Get-DescriptorFixture {
        param([switch] $DaclLast)
        $sid = Get-SidFixture -SubAuthority 21, 1, 512
        $ace = @(
            (Get-AceFixture -Type 0 -Flags 0 -Mask 0xF01FF -Sid $sid),
            (Get-AceFixture -Type 5 -Flags 0x10 -Mask 0x20 -Sid $sid -ObjectFlags 3),
            (Get-AceFixture -Type 1 -Flags 0 -Mask 0x40000 -Sid $sid),
            (Get-AceFixture -Type 6 -Flags 0x08 -Mask 0x100 -Sid $sid -ObjectFlags 1),
            (Get-AceFixture -Type 9 -Flags 0 -Mask 1 -Sid $sid)
        )
        $size = 8
        foreach ($item in $ace) { $size += $item.Length }
        $acl = [System.Collections.Generic.List[byte]]::new()
        $acl.AddRange([byte[]](2, 0))
        $acl.AddRange([BitConverter]::GetBytes([uint16]$size))
        $acl.AddRange([BitConverter]::GetBytes([uint16]$ace.Count))
        $acl.AddRange([byte[]](0, 0))
        foreach ($item in $ace) { $acl.AddRange($item) }
        $ownerOffset = 20 + $acl.Count
        $daclOffset = 20
        if ($DaclLast) {
            $ownerOffset = 20
            $daclOffset = 20 + $sid.Length
        }
        $descriptor = [System.Collections.Generic.List[byte]]::new()
        $descriptor.AddRange([byte[]](1, 0, 4, 0x84))
        $descriptor.AddRange([BitConverter]::GetBytes([uint32]$ownerOffset))
        $descriptor.AddRange([byte[]](0, 0, 0, 0, 0, 0, 0, 0))
        $descriptor.AddRange([BitConverter]::GetBytes([uint32]$daclOffset))
        if ($DaclLast) {
            $descriptor.AddRange($sid)
            $descriptor.AddRange($acl)
        } else {
            $descriptor.AddRange($acl)
            $descriptor.AddRange($sid)
        }
        , $descriptor.ToArray()
    }

    function Get-DerFixture {
        param([int] $Tag, [object[]] $Part = @())
        $content = [System.Collections.Generic.List[byte]]::new()
        foreach ($item in $Part) { foreach ($value in $item) { $content.Add([byte]$value) } }
        $header = @($Tag)
        if ($content.Count -ge 128) {
            $header += 0x82, ($content.Count -shr 8), ($content.Count -band 0xFF)
        } else {
            $header += $content.Count
        }
        , [byte[]]($header + $content.ToArray())
    }

    # The seed itself, every prefix of it, every offset set to a boundary value, a few random
    # byte changes and some random bytes. -Stride thins out the offsets of a long seed.
    function Get-MutantList {
        param([byte[]] $Seed, [int] $Stride = 1, [int] $ChangeCount = 60, [int] $RandomCount = 40)
        $list = [System.Collections.Generic.List[object]]::new()
        $list.Add([byte[]]$Seed.Clone())
        for ($length = 1; $length -lt $Seed.Length; $length++) {
            $list.Add([byte[]]$Seed[0..($length - 1)])
        }
        for ($offset = 0; $offset -lt $Seed.Length; $offset++) {
            if ($offset -ge 64 -and $offset % $Stride -ne 0) { continue }
            foreach ($value in 0, 0x7F, 0x80, 0xFF) {
                $copy = [byte[]]$Seed.Clone()
                $copy[$offset] = $value
                $list.Add($copy)
            }
        }
        for ($count = 0; $count -lt $ChangeCount; $count++) {
            $copy = [byte[]]$Seed.Clone()
            foreach ($change in 0..(Get-NextNumber -Limit 4)) {
                $copy[(Get-NextNumber -Limit $copy.Length)] = Get-NextNumber -Limit 256
            }
            $list.Add($copy)
        }
        for ($count = 0; $count -lt $RandomCount; $count++) {
            $random = [byte[]]::new(1 + (Get-NextNumber -Limit 48))
            for ($index = 0; $index -lt $random.Length; $index++) {
                $random[$index] = Get-NextNumber -Limit 256
            }
            $list.Add($random)
        }
        , $list.ToArray()
    }

    # The descriptor with the size in its ACL header changed by -8 to +8 bytes, and with a size
    # below the header and no entries.
    function Get-AclSizeMutantList {
        param([byte[]] $Seed)
        $daclOffset = [BitConverter]::ToUInt32($Seed, 16)
        $size = [BitConverter]::ToUInt16($Seed, $daclOffset + 2)
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($delta in -8..8) {
            if ($delta -eq 0) { continue }
            $copy = [byte[]]$Seed.Clone()
            [BitConverter]::GetBytes([uint16]($size + $delta)).CopyTo($copy, $daclOffset + 2)
            $list.Add($copy)
        }
        foreach ($small in 0..7) {
            $copy = [byte[]]$Seed.Clone()
            [BitConverter]::GetBytes([uint16]$small).CopyTo($copy, $daclOffset + 2)
            [BitConverter]::GetBytes([uint16]0).CopyTo($copy, $daclOffset + 4)
            $list.Add($copy)
        }
        , $list.ToArray()
    }

    function Format-Violation {
        param([object[]] $Violation, [object[]] $Case)
        $text = foreach ($item in ($Violation | Select-Object -First 3)) {
            $first = $Case[$item.Index] | Select-Object -First 40
            $head = ($first | ForEach-Object { $_.ToString('x2') }) -join ''
            "$($item.Reason) [$($Case[$item.Index].Length) bytes: $head]"
        }
        $text -join '; '
    }

    $script:rocaPrime = 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167

    # Whether the modulus lies, for every small prime, in the group that 65537 generates: an
    # element of a cyclic group is in the subgroup of a generator g when its order divides
    # the order of g. This does not enumerate the group, as the code under test does.
    function Test-RocaReference {
        param([byte[]] $Modulus)
        $value = [System.Numerics.BigInteger]::Zero
        foreach ($byte in $Modulus) { $value = $value * 256 + $byte }
        foreach ($prime in $script:rocaPrime) {
            $remainder = [int]($value % $prime)
            if ($remainder -eq 0) { return $false }
            $generator = 65537 % $prime
            $order = 1
            $power = $generator
            while ($power -ne 1) {
                $power = ($power * $generator) % $prime
                $order++
            }
            $check = [System.Numerics.BigInteger]::ModPow($remainder, $order, $prime)
            if ($check -ne 1) { return $false }
        }
        return $true
    }

    # A modulus that, by the Chinese remainder theorem, has a remainder inside the group of
    # 65537 for every small prime, except for the prime at -ZeroAt (remainder 0).
    function Get-RocaModulus {
        param([int] $ZeroAt = -1)
        $product = [System.Numerics.BigInteger]::One
        foreach ($prime in $script:rocaPrime) { $product *= $prime }
        $value = [System.Numerics.BigInteger]::Zero
        for ($index = 0; $index -lt $script:rocaPrime.Count; $index++) {
            $prime = $script:rocaPrime[$index]
            $generator = 65537 % $prime
            $wanted = 1
            $steps = Get-NextNumber -Limit 200
            for ($step = 0; $step -lt $steps; $step++) { $wanted = ($wanted * $generator) % $prime }
            if ($index -eq $ZeroAt) { $wanted = 0 }
            $rest = $product / $prime
            $inverse = [System.Numerics.BigInteger]::ModPow($rest % $prime, $prime - 2, $prime)
            $value += $wanted * $rest * $inverse
        }
        $size = 1830 + (Get-NextNumber -Limit 40)
        $value = $value % $product + $product * [System.Numerics.BigInteger]::Pow(2, $size)
        $bytes = $value.ToByteArray()
        [array]::Reverse($bytes)
        $skip = 0
        while ($skip -lt $bytes.Length - 1 -and $bytes[$skip] -eq 0) { $skip++ }
        , [byte[]]$bytes[$skip..($bytes.Length - 1)]
    }

    # Random moduli (almost never carrying the fingerprint), moduli that carry it, and moduli
    # that miss it for exactly one prime, once for each prime.
    function Get-RocaCase {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($count in 1..300) {
            $length = Get-NextNumber -Limit 49
            $random = [byte[]]::new($length)
            for ($index = 0; $index -lt $length; $index++) {
                $random[$index] = Get-NextNumber -Limit 256
            }
            $list.Add($random)
        }
        foreach ($count in 1..20) { $list.Add((Get-RocaModulus)) }
        foreach ($zeroAt in 0..($script:rocaPrime.Count - 1)) {
            $list.Add((Get-RocaModulus -ZeroAt $zeroAt))
        }
        , $list.ToArray()
    }

    $modulus = Get-DerFixture -Tag 2 -Part @(, [byte[]](@(0, 0xC1) + @(0x55) * 63))
    $exponent = Get-DerFixture -Tag 2 -Part @(, [byte[]](1, 0, 1))
    $key = Get-DerFixture -Tag 0x30 -Part @($modulus, $exponent)
    $script:keyCase = Get-MutantList -Seed $key
    $script:certificateCase = Get-MutantList -Seed $script:certificate -Stride 11
    $first = Get-DescriptorFixture
    $last = Get-DescriptorFixture -DaclLast
    $firstCase = Get-MutantList -Seed $first
    $lastCase = Get-MutantList -Seed $last -Stride 3 -ChangeCount 20 -RandomCount 0
    $firstSize = Get-AclSizeMutantList -Seed $first
    $lastSize = Get-AclSizeMutantList -Seed $last
    $script:descriptorCase = $firstCase + $lastCase + $firstSize + $lastSize
}

Describe 'ANSSI parsers on damaged input' {
    It 'Get-MtAnssiAdDerElement returns elements that tile the data or names the DER problem' {
        $cases = @($script:keyCase) + @($script:certificateCase)
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                $bytes = $Cases[$index]
                try {
                    $element = @(Get-MtAnssiAdDerElement -Byte $bytes)
                } catch {
                    if ($_.Exception.Message -notmatch '^The DER ') {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = $_.Exception.Message
                        })
                    }
                    continue
                }
                $start = 0
                foreach ($item in $element) {
                    $headerLength = $item.ContentOffset - $start
                    if ($headerLength -lt 2 -or $headerLength -gt 6 -or
                        $item.Length -ne $item.End - $item.ContentOffset) {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = "bad element at $start"
                        })
                    }
                    $start = $item.End
                }
                if ($start -ne $bytes.Length) {
                    $found.Add([PSCustomObject]@{
                        Index = $index
                        Reason = "elements end at $start"
                    })
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'Get-MtAnssiAdRsaPublicKey and Get-MtAnssiAdRsaKeyProblem return sound results or an error' {
        $cases = @($script:keyCase)
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            $accepted = '^The (DER|RSA public key) '
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                $bytes = $Cases[$index]
                try {
                    $key = Get-MtAnssiAdRsaPublicKey -Key $bytes
                    $bits = 0
                    if ($key.Modulus.Length -gt 0) {
                        $bits = ($key.Modulus.Length - 1) * 8 +
                            [Convert]::ToString($key.Modulus[0], 2).Length
                        if ($key.Modulus[0] -eq 0) {
                            $found.Add([PSCustomObject]@{
                                Index = $index
                                Reason = 'leading zero byte'
                            })
                        }
                    }
                    if ($key.BitLength -ne $bits -or $key.Exponent -isnot [uint64]) {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = 'bit length or exponent'
                        })
                    }
                } catch {
                    if ($_.Exception.Message -notmatch $accepted) {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = $_.Exception.Message
                        })
                    }
                }
                try {
                    foreach ($problem in @(Get-MtAnssiAdRsaKeyProblem -Key $bytes)) {
                        if ($problem.Level -notin 1, 3 -or -not $problem.Text) {
                            $found.Add([PSCustomObject]@{ Index = $index; Reason = 'bad problem' })
                        }
                    }
                } catch {
                    if ($_.Exception.Message -notmatch $accepted) {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = $_.Exception.Message
                        })
                    }
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'Get-MtAnssiAdCertificateProblem never throws and reports a level for every problem' {
        $cases = @($script:certificateCase)
        $result = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            $levels = @{}
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                try {
                    $item = Get-MtAnssiAdCertificateProblem -Certificate $Cases[$index]
                } catch {
                    $found.Add([PSCustomObject]@{
                        Index = $index
                        Reason = "threw: $($_.Exception.Message)"
                    })
                    continue
                }
                $levels["$($item.Level)"] = $true
                $count = @($item.Problem).Count
                $withoutLevel = $null -eq $item.Level
                if ($item.Level -notin $null, 1, 2, 3 -or $withoutLevel -ne ($count -eq 0) -or
                    $item.Subject -isnot [string]) {
                    $found.Add([PSCustomObject]@{
                        Index = $index
                        Reason = "level $($item.Level), $count problems"
                    })
                }
            }
            [PSCustomObject]@{ Violation = $found.ToArray(); Level = @($levels.Keys) }
        }

        @($result.Violation).Count | Should -Be 0 -Because (
            Format-Violation -Violation $result.Violation -Case $cases)
        $result.Level | Should -Contain '1' -Because 'the undamaged certificate has a ROCA key'
        $result.Level | Should -Contain '2' -Because 'damaged certificates cannot be parsed'
    }

    It 'Get-MtAnssiAdSignatureWeakness returns a verdict or names the DER problem' {
        $cases = @($script:certificateCase)
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                try {
                    $weak = Get-MtAnssiAdSignatureWeakness -Certificate $Cases[$index] `
                        -Algorithm '1.2.840.113549.1.1.10'
                    if ($weak -isnot [bool]) {
                        $found.Add([PSCustomObject]@{ Index = $index; Reason = 'not a boolean' })
                    }
                } catch {
                    if ($_.Exception.Message -notmatch '^The DER ') {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = $_.Exception.Message
                        })
                    }
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'Get-MtLdapSecurityDescriptorAce and its readers return complete lists or name the problem' {
        $cases = @($script:descriptorCase | Where-Object { $_.Length -gt 0 })
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            $accepted = ('^(The security descriptor has|The DACL at position|Entry \d+ of the' +
                ' DACL|') +
                'The SID at position|The SID of entry)'
            $shape = '^S-\d+-\d+(-\d+)*$'
            $fail = { param($i, $r) $found.Add([PSCustomObject]@{ Index = $i; Reason = $r }) }
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                $bytes = $Cases[$index]
                $ace = $null; $aceError = $null; $allow = $null; $allowError = $null
                try { $ace = @(Get-MtLdapSecurityDescriptorAce `
                    -Descriptor $bytes) } catch { $aceError = $_.Exception.Message }
                try { $allow = @(Get-MtLdapSecurityDescriptorAllowSid `
                    -Descriptor $bytes) } catch { $allowError = $_.Exception.Message }
                foreach ($message in $aceError, $allowError) {
                    if ($message -and
                        $message -notmatch $accepted) { & $fail $index "message: $message" }
                }
                if (($null -eq $aceError) -ne ($null -eq $allowError)) {
                    & $fail $index 'readers disagree'
                }
                if ($null -eq $aceError) {
                    $declared = 0
                    $offset = [BitConverter]::ToUInt32($bytes, 16)
                    if ($offset -ne 0) { $declared = [BitConverter]::ToUInt16($bytes, $offset + 4) }
                    if ($ace.Count -ne $declared) {
                        & $fail $index "$($ace.Count) of $declared entries"
                    }
                    # Walk the announced sizes without the code under test: the DACL must lie
                    # inside the descriptor and every entry that was returned inside the DACL.
                    $aclSize = [BitConverter]::ToUInt16($bytes, $offset + 2)
                    $daclEnd = $offset + $aclSize
                    if ($offset -ne 0 -and ($daclEnd -gt $bytes.Length -or $aclSize -lt 8)) {
                        & $fail $index "DACL of $aclSize bytes at $offset in $($bytes.Length)"
                    }
                    $position = $offset + 8
                    for ($entryIndex = 0; $entryIndex -lt $declared; $entryIndex++) {
                        $size = [BitConverter]::ToUInt16($bytes, $position + 2)
                        if ($position + $size -gt $daclEnd) {
                            & $fail $index "entry $entryIndex ends beyond the DACL"
                        }
                        $position += $size
                    }
                    $allowed = $ace | Where-Object { $_.Type -eq 'Allow' }
                    $expected = @($allowed | ForEach-Object { $_.Sid })
                    $actual = @($allow) -join ' '
                    if (($expected -join ' ') -ne $actual) { & $fail $index 'allow list differs' }
                    foreach ($entry in $ace) {
                        if ($entry.Type -eq 'Other' -and
                            $null -ne $entry.Sid) { & $fail $index 'Other with SID' }
                        if ($entry.Type -ne 'Other' -and
                            $entry.Sid -notmatch $shape) { & $fail $index 'SID shape' }
                    }
                }
                try {
                    $owner = Get-MtLdapSecurityDescriptorOwnerSid -Descriptor $bytes
                    if ($null -ne $owner -and
                        $owner -notmatch $shape) { & $fail $index 'owner shape' }
                } catch {
                    if ($_.Exception.Message -notmatch ('^The SID at position' +
                        ' ')) { & $fail $index "owner: $($_.Exception.Message)" }
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'ConvertFrom-MtLdapBinarySid returns a SID of the announced size or says it does not fit' {
        $sid = Get-SidFixture -SubAuthority 21, 1, 2, 3, 512
        $cases = @(, $sid) + @($script:descriptorCase | Select-Object -Skip 120 -First 12)
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                $bytes = $Cases[$index]
                for ($offset = -3; $offset -le $bytes.Length + 3; $offset++) {
                    try {
                        $text = ConvertFrom-MtLdapBinarySid -Bytes $bytes -Offset $offset
                        if ($offset -lt 0) {
                            $found.Add([PSCustomObject]@{
                                Index = $index
                                Reason = "returned '$text' for the negative offset $offset"
                            })
                            continue
                        }
                        $parts = $text -split '-'
                        $announced = 3 + $bytes[$offset + 1]
                        if ($text -notmatch '^S-\d+-\d+(-\d+)*$' -or $parts.Count -ne $announced) {
                            $found.Add([PSCustomObject]@{
                                Index = $index
                                Reason = "offset ${offset}: $text"
                            })
                        }
                    } catch {
                        if ($_.Exception.Message -notmatch '^The SID at position ') {
                            $found.Add([PSCustomObject]@{
                                Index = $index
                                Reason = $_.Exception.Message
                            })
                        }
                    }
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'Get-MtAnssiAdDnsZoneAllowUpdate never throws and reads the property as documented' {
        $seed = [byte[]](@(1, 0, 0, 0) + @(0) * 12 + @(2, 0, 0, 0, 1))
        $cases = Get-MutantList -Seed $seed -ChangeCount 150
        $violations = InModuleScope Maester -Parameters @{ Cases = $cases } {
            param($Cases)
            $found = [System.Collections.Generic.List[object]]::new()
            for ($index = 0; $index -lt $Cases.Count; $index++) {
                $bytes = $Cases[$index]
                $expected = $null
                if ($bytes.Length -ge 21 -and [BitConverter]::ToUInt32($bytes, 16) -eq 2 -and
                    [BitConverter]::ToUInt32($bytes, 0) -ne 0) {
                    $expected = [int]$bytes[20]
                }
                try {
                    $value = Get-MtAnssiAdDnsZoneAllowUpdate -Property @(, $bytes)
                    if ("$value" -ne "$expected" -or ($null -ne $value -and $value -isnot [int])) {
                        $found.Add([PSCustomObject]@{
                            Index = $index
                            Reason = "got '$value', expected '$expected'"
                        })
                    }
                } catch {
                    $found.Add([PSCustomObject]@{
                        Index = $index
                        Reason = "threw: $($_.Exception.Message)"
                    })
                }
            }
            , $found.ToArray()
        }

        @($violations).Count |
            Should -Be 0 -Because (Format-Violation -Violation $violations -Case $cases)
    }

    It 'ConvertFrom-MtAnssiAdGpLink keeps every link and reads the option bits of any number' {
        $option = '1', '0', '2', '3', '4', '7', '10', '99999999999', '2147483648', '4294967297',
            ('9' * 400), ('1' + '0' * 60), ('2' + '0' * 60)
        $fragment = '[', ']', ';', 'LDAP://', 'ldap://', 'cn={A}', 'DC=x', '0', '1', '3',
            '99999999999', ' ', '-'
        $random = foreach ($count in 1..300) {
            $pick = foreach ($step in 0..(Get-NextNumber -Limit 12)) {
                $fragment[(Get-NextNumber -Limit $fragment.Count)]
            }
            $pick -join ''
        }
        $value = @($option | ForEach-Object { "[LDAP://cn={A},DC=x;$_]" }) + $random

        $result = InModuleScope Maester -Parameters @{ Value = $value } {
            param($Value)
            foreach ($text in $Value) {
                try {
                    [PSCustomObject]@{
                        Link = @(ConvertFrom-MtAnssiAdGpLink -Value $text)
                        Error = $null
                    }
                } catch {
                    [PSCustomObject]@{ Link = @(); Error = $_.Exception.Message }
                }
            }
        }

        $failures = for ($index = 0; $index -lt $value.Count; $index++) {
            $item = $result[$index]
            if ($item.Error) { "threw on '$($value[$index])': $($item.Error)"; continue }
            foreach ($link in $item.Link) {
                if (-not $link.Gpo -or $link.Gpo -match '[;\]]') {
                    "bad entry in '$($value[$index])'"
                }
            }
            if ($index -lt $option.Count) {
                $number = [System.Numerics.BigInteger]::Parse($option[$index])
                $disabled = -not ($number -band 1).IsZero
                $enforced = -not ($number -band 2).IsZero
                if (@($item.Link).Count -ne 1 -or $item.Link[0].Disabled -ne $disabled -or
                    $item.Link[0].Enforced -ne $enforced) {
                    "option $($option[$index].Substring(0, [Math]::Min(8, $option[$index].Length)))"
                }
            }
        }
        $failures | Should -BeNullOrEmpty
    }

    It 'Get-MtAnssiAdRocaFingerprint agrees with an independent calculation on any modulus' {
        $cases = Get-RocaCase
        $actual = @(InModuleScope Maester -Parameters @{ Cases = $cases } {
                param($Cases)
                foreach ($modulus in $Cases) { Get-MtAnssiAdRocaFingerprint -Modulus $modulus }
            })

        $differences = for ($index = 0; $index -lt $cases.Count; $index++) {
            $expected = Test-RocaReference -Modulus $cases[$index]
            if ($actual[$index] -ne $expected) {
                "$($cases[$index].Length) bytes: got $($actual[$index]), expected $expected"
            }
        }
        $differences | Should -BeNullOrEmpty
        @($cases | Where-Object { Test-RocaReference -Modulus $_ }).Count |
            Should -BeGreaterOrEqual 20 -Because 'the constructed moduli carry the fingerprint'
    }
}
