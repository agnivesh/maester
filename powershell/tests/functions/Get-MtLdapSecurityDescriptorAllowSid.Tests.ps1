BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function ConvertTo-BinarySid {
        param([string] $Sid)
        $parts = $Sid -split '-'
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.Add([byte]$parts[1])
        $bytes.Add([byte]($parts.Count - 3))
        $authority = [uint64]$parts[2]
        for ($shift = 40; $shift -ge 0; $shift -= 8) {
            $bytes.Add([byte](($authority -shr $shift) -band 0xff))
        }
        for ($index = 3; $index -lt $parts.Count; $index++) {
            $bytes.AddRange([BitConverter]::GetBytes([uint32]$parts[$index]))
        }
        , $bytes.ToArray()
    }

    function ConvertTo-BinaryAce {
        param([byte] $Type, [string] $Sid, [uint32] $Flags = 0)
        $body = [System.Collections.Generic.List[byte]]::new()
        $body.AddRange([BitConverter]::GetBytes([uint32]0xF01FF))
        if ($Type -ge 5) {
            $body.AddRange([BitConverter]::GetBytes($Flags))
            if ($Flags -band 1) { $body.AddRange([byte[]]::new(16)) }
            if ($Flags -band 2) { $body.AddRange([byte[]]::new(16)) }
        }
        $body.AddRange((ConvertTo-BinarySid -Sid $Sid))
        $ace = [System.Collections.Generic.List[byte]]::new()
        $ace.Add($Type)
        $ace.Add(0)
        $ace.AddRange([BitConverter]::GetBytes([uint16](4 + $body.Count)))
        $ace.AddRange($body)
        , $ace.ToArray()
    }

    function ConvertTo-BinaryDescriptor {
        param([object[]] $Ace = @(), [switch] $NoDacl)
        $header = [System.Collections.Generic.List[byte]]::new()
        $header.AddRange([byte[]](1, 0, 4, 0x80))
        $owner = ConvertTo-BinarySid -Sid 'S-1-5-32-544'
        $header.AddRange([BitConverter]::GetBytes([uint32]20))
        $header.AddRange([BitConverter]::GetBytes([uint32]0))
        $header.AddRange([BitConverter]::GetBytes([uint32]0))
        $daclOffset = 0
        if (-not $NoDacl) { $daclOffset = 20 + $owner.Length }
        $header.AddRange([BitConverter]::GetBytes([uint32]$daclOffset))
        $header.AddRange($owner)
        if (-not $NoDacl) {
            $entries = [System.Collections.Generic.List[byte]]::new()
            foreach ($item in $Ace) {
                $aceBytes = ConvertTo-BinaryAce -Type $item.Type -Sid $item.Sid -Flags $item.Flags
                $entries.AddRange($aceBytes)
            }
            $header.AddRange([byte[]](2, 0))
            $header.AddRange([BitConverter]::GetBytes([uint16](8 + $entries.Count)))
            $header.AddRange([BitConverter]::GetBytes([uint16]$Ace.Count))
            $header.AddRange([byte[]](0, 0))
            $header.AddRange($entries)
        }
        , $header.ToArray()
    }

    function Get-AllowSid {
        param([byte[]] $Descriptor)
        InModuleScope Maester -Parameters @{ Descriptor = $Descriptor } {
            param($Descriptor)
            Get-MtLdapSecurityDescriptorAllowSid -Descriptor $Descriptor
        }
    }
}

Describe 'Get-MtLdapSecurityDescriptorAllowSid' {
    It 'returns the SID of an access-allowed entry' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105' })

        @(Get-AllowSid -Descriptor $bytes) -join ',' | Should -BeExactly 'S-1-5-21-1-2-3-1105'
    }

    It 'returns several allowed SIDs in order and skips deny entries' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 1; Sid = 'S-1-5-21-1-2-3-1107' }
            @{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105' }
            @{ Type = 6; Sid = 'S-1-5-21-1-2-3-1108' }
            @{ Type = 0; Sid = 'S-1-5-32-544' }
        )

        @(Get-AllowSid -Descriptor $bytes) -join ',' |
            Should -BeExactly 'S-1-5-21-1-2-3-1105,S-1-5-32-544'
    }

    It 'reads the SID of an object entry with flags <Flags>' -ForEach @(
        @{ Flags = 0 }
        @{ Flags = 1 }
        @{ Flags = 2 }
        @{ Flags = 3 }
    ) {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 5; Sid = 'S-1-5-21-1-2-3-1106'; Flags = $Flags }
            @{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105' }
        )

        @(Get-AllowSid -Descriptor $bytes) -join ',' |
            Should -BeExactly 'S-1-5-21-1-2-3-1106,S-1-5-21-1-2-3-1105'
    }

    It 'reads a well-known SID with a large identifier authority' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-16-12288' })

        @(Get-AllowSid -Descriptor $bytes) -join ',' | Should -BeExactly 'S-1-16-12288'
    }

    It 'returns nothing for a DACL without entries' {
        @(Get-AllowSid -Descriptor (ConvertTo-BinaryDescriptor -Ace @())).Count | Should -Be 0
    }

    It 'returns nothing for a descriptor without DACL' {
        @(Get-AllowSid -Descriptor (ConvertTo-BinaryDescriptor -NoDacl)).Count | Should -Be 0
    }

    It 'throws for a descriptor shorter than its header' {
        { Get-AllowSid -Descriptor ([byte[]](1, 0, 4)) } | Should -Throw '*fewer than its header*'
    }

    It 'throws when the DACL lies outside the descriptor' {
        $bytes = ConvertTo-BinaryDescriptor -NoDacl
        [BitConverter]::GetBytes([uint32]999).CopyTo($bytes, 16)

        { Get-AllowSid -Descriptor $bytes } | Should -Throw '*does not fit*'
    }

    It 'throws when an entry is cut off' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105' })
        $cut = [byte[]]$bytes[0..($bytes.Length - 10)]

        { Get-AllowSid -Descriptor $cut } | Should -Throw '*does not fit*'
    }

    It 'throws when the entry count is larger than the entries present' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105' })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]2).CopyTo($bytes, $daclOffset + 4)

        { Get-AllowSid -Descriptor $bytes } | Should -Throw '*Entry 1*'
    }
}
