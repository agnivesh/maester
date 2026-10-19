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
        param([hashtable] $Entry)
        $body = [System.Collections.Generic.List[byte]]::new()
        $mask = 0x20
        if ($Entry.ContainsKey('Mask')) { $mask = $Entry.Mask }
        $body.AddRange([BitConverter]::GetBytes([uint32]$mask))
        if ($Entry.Type -eq 5 -or $Entry.Type -eq 6) {
            $objectFlags = 0
            if ($Entry.ObjectType) { $objectFlags = $objectFlags -bor 1 }
            if ($Entry.InheritedObjectType) { $objectFlags = $objectFlags -bor 2 }
            $body.AddRange([BitConverter]::GetBytes([uint32]$objectFlags))
            if ($Entry.ObjectType) { $body.AddRange(([guid]$Entry.ObjectType).ToByteArray()) }
            if ($Entry.InheritedObjectType) {
                $body.AddRange(([guid]$Entry.InheritedObjectType).ToByteArray())
            }
        }
        $body.AddRange((ConvertTo-BinarySid -Sid $Entry.Sid))
        $ace = [System.Collections.Generic.List[byte]]::new()
        $ace.Add([byte]$Entry.Type)
        $ace.Add([byte]$Entry.Flags)
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
            foreach ($item in $Ace) { $entries.AddRange((ConvertTo-BinaryAce -Entry $item)) }
            $header.AddRange([byte[]](2, 0))
            $header.AddRange([BitConverter]::GetBytes([uint16](8 + $entries.Count)))
            $header.AddRange([BitConverter]::GetBytes([uint16]$Ace.Count))
            $header.AddRange([byte[]](0, 0))
            $header.AddRange($entries)
        }
        , $header.ToArray()
    }

    function Get-Ace {
        param([byte[]] $Descriptor)
        InModuleScope Maester -Parameters @{ Descriptor = $Descriptor } {
            param($Descriptor)
            Get-MtLdapSecurityDescriptorAce -Descriptor $Descriptor
        }
    }

    $script:memberGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    $script:groupGuid = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
}

Describe 'Get-MtLdapSecurityDescriptorAce' {
    It 'reads a basic allow entry' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105'; Mask = 0x40000; Flags = 0 }
        )

        $ace = @(Get-Ace -Descriptor $bytes)

        $ace.Count | Should -Be 1
        $ace[0].Index | Should -Be 0
        $ace[0].Type | Should -BeExactly 'Allow'
        $ace[0].AceType | Should -Be 0
        $ace[0].Mask | Should -Be 0x40000
        $ace[0].ObjectType | Should -BeExactly ''
        $ace[0].InheritedObjectType | Should -BeExactly ''
        $ace[0].InheritOnly | Should -Be $false
        $ace[0].IsInherited | Should -Be $false
        $ace[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1105'
    }

    It 'reads a basic deny entry' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 1; Sid = 'S-1-1-0'; Flags = 0 })

        $ace = @(Get-Ace -Descriptor $bytes)

        $ace[0].Type | Should -BeExactly 'Deny'
        $ace[0].AceType | Should -Be 1
        $ace[0].Sid | Should -BeExactly 'S-1-1-0'
    }

    It 'reads type <Type> as <Expected> with object flags <Name>' -ForEach @(
        @{ Type = 5; Expected = 'Allow'; Name = 'none'; Object = $false; Inherited = $false }
        @{ Type = 5; Expected = 'Allow'; Name = 'object'; Object = $true; Inherited = $false }
        @{ Type = 6; Expected = 'Deny'; Name = 'inherited'; Object = $false; Inherited = $true }
        @{ Type = 6; Expected = 'Deny'; Name = 'both'; Object = $true; Inherited = $true }
    ) {
        $entry = @{ Type = $Type; Sid = 'S-1-5-21-1-2-3-1106'; Flags = 0 }
        if ($Object) { $entry.ObjectType = $script:memberGuid }
        if ($Inherited) { $entry.InheritedObjectType = $script:groupGuid }
        $system = @{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 }
        $bytes = ConvertTo-BinaryDescriptor -Ace @($entry, $system)

        $ace = @(Get-Ace -Descriptor $bytes)

        $ace[0].Type | Should -BeExactly $Expected
        $ace[0].AceType | Should -Be $Type
        $ace[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1106'
        $expectedObject = ''
        if ($Object) { $expectedObject = $script:memberGuid }
        $expectedInherited = ''
        if ($Inherited) { $expectedInherited = $script:groupGuid }
        $ace[0].ObjectType | Should -BeExactly $expectedObject
        $ace[0].InheritedObjectType | Should -BeExactly $expectedInherited
        $ace[1].Index | Should -Be 1
        $ace[1].Sid | Should -BeExactly 'S-1-5-18'
    }

    It 'reads flags <Flags> as InheritOnly <InheritOnly>, IsInherited <IsInherited>' -ForEach @(
        @{ Flags = 0x02; InheritOnly = $false; IsInherited = $false }
        @{ Flags = 0x0A; InheritOnly = $true; IsInherited = $false }
        @{ Flags = 0x12; InheritOnly = $false; IsInherited = $true }
        @{ Flags = 0x1A; InheritOnly = $true; IsInherited = $true }
    ) {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-11'; Flags = $Flags })

        $ace = @(Get-Ace -Descriptor $bytes)

        $ace[0].InheritOnly | Should -Be $InheritOnly
        $ace[0].IsInherited | Should -Be $IsInherited
    }

    It 'returns other entry types without a SID but with their mask' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 2; Sid = 'S-1-1-0'; Mask = 0x10; Flags = 0 }
            @{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 }
        )

        $ace = @(Get-Ace -Descriptor $bytes)

        $ace[0].Type | Should -BeExactly 'Other'
        $ace[0].AceType | Should -Be 2
        $ace[0].Mask | Should -Be 0x10
        $ace[0].Sid | Should -BeNullOrEmpty
        $ace[1].Sid | Should -BeExactly 'S-1-5-18'
    }

    It 'reads a full mask with the highest bit set' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 0; Sid = 'S-1-5-18'; Mask = [uint32]2147483648; Flags = 0 }
        )

        (@(Get-Ace -Descriptor $bytes))[0].Mask | Should -Be ([uint32]2147483648)
    }

    It 'returns nothing for a DACL without entries' {
        @(Get-Ace -Descriptor (ConvertTo-BinaryDescriptor -Ace @())).Count | Should -Be 0
    }

    It 'returns nothing for a descriptor without DACL' {
        @(Get-Ace -Descriptor (ConvertTo-BinaryDescriptor -NoDacl)).Count | Should -Be 0
    }

    It 'throws for a descriptor shorter than its header' {
        { Get-Ace -Descriptor ([byte[]]::new(19)) } | Should -Throw '*fewer than its header*'
    }

    It 'reads a descriptor of exactly the header size' {
        @(Get-Ace -Descriptor ([byte[]]::new(20))).Count | Should -Be 0
    }

    It 'throws when the DACL header lies outside the descriptor' {
        $bytes = ConvertTo-BinaryDescriptor -NoDacl
        [BitConverter]::GetBytes([uint32]($bytes.Length - 7)).CopyTo($bytes, 16)

        { Get-Ace -Descriptor $bytes } | Should -Throw '*DACL at position*'
    }

    It 'throws that the DACL does not fit for an offset of <Offset> (above 2 GB)' -ForEach @(
        @{ Offset = [uint32]2147483648 }
        @{ Offset = [uint32]2147483668 }
        @{ Offset = [uint32]4294967295 }
    ) {
        $bytes = ConvertTo-BinaryDescriptor -NoDacl
        [BitConverter]::GetBytes($Offset).CopyTo($bytes, 16)

        { Get-Ace -Descriptor $bytes } | Should -Throw "*DACL at position $Offset does not fit*"
    }

    It 'throws when the DACL announces <Name>' -ForEach @(
        @{ Name = 'a size below its header'; Size = 7 }
        @{ Name = 'a size of 0'; Size = 0 }
        @{ Name = 'one byte more than the descriptor holds'; Size = -1 }
        @{ Name = 'the largest size'; Size = 65535 }
    ) {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        $size = $Size
        if ($Size -eq -1) { $size = $bytes.Length - $daclOffset + 1 }
        [BitConverter]::GetBytes([uint16]$size).CopyTo($bytes, $daclOffset + 2)

        { Get-Ace -Descriptor $bytes } |
            Should -Throw "*The DACL at position $daclOffset has a size of $size*"
    }

    It 'throws when an entry ends beyond the DACL but inside the descriptor' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        $size = [BitConverter]::ToUInt16($bytes, $daclOffset + 2)
        [BitConverter]::GetBytes([uint16]($size - 1)).CopyTo($bytes, $daclOffset + 2)

        { Get-Ace -Descriptor $bytes } | Should -Throw '*Entry 0 of the DACL has a size*'
    }

    It 'does not read bytes after the DACL as another entry' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        $extended = [byte[]]($bytes + [byte[]](@(0, 0, 12, 0, 0, 0, 0, 0) + @(0) * 4))
        [BitConverter]::GetBytes([uint16]2).CopyTo($extended, $daclOffset + 4)

        { Get-Ace -Descriptor $extended } |
            Should -Throw '*Entry 1 of the DACL does not fit in the DACL*'
    }

    It 'reads a DACL that is followed by other data or has padding inside its size' -ForEach @(
        @{ Name = 'data after the DACL'; Padding = 0; Trailing = 6 }
        @{ Name = 'padding inside the announced size'; Padding = 4; Trailing = 0 }
    ) {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        $size = [BitConverter]::ToUInt16($bytes, $daclOffset + 2)
        $extended = [byte[]]($bytes + [byte[]]::new($Padding + $Trailing))
        [BitConverter]::GetBytes([uint16]($size + $Padding)).CopyTo($extended, $daclOffset + 2)

        $ace = @(Get-Ace -Descriptor $extended)

        $ace.Count | Should -Be 1
        $ace[0].Sid | Should -BeExactly 'S-1-5-18'
    }

    It 'reads a DACL header that ends exactly at the end of the descriptor' {
        $header = [byte[]](ConvertTo-BinaryDescriptor -NoDacl)
        $bytes = [System.Collections.Generic.List[byte]]::new($header)
        $offset = $bytes.Count
        $bytes.AddRange([byte[]](2, 0, 8, 0, 0, 0, 0, 0))
        $array = $bytes.ToArray()
        [BitConverter]::GetBytes([uint32]$offset).CopyTo($array, 16)

        @(Get-Ace -Descriptor $array).Count | Should -Be 0
    }

    It 'throws when the entry count is larger than the entries present' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]2).CopyTo($bytes, $daclOffset + 4)

        { Get-Ace -Descriptor $bytes } | Should -Throw '*Entry 1 of the DACL does not fit*'
    }

    It 'throws when an entry is cut off' {
        $entry = @{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105'; Flags = 0 }
        $bytes = ConvertTo-BinaryDescriptor -Ace @($entry)
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        $cut = [byte[]]$bytes[0..($bytes.Length - 2)]
        [BitConverter]::GetBytes([uint16]($cut.Length - $daclOffset)).CopyTo($cut, $daclOffset + 2)

        { Get-Ace -Descriptor $cut } | Should -Throw '*Entry 0 of the DACL has a size*'
    }

    It 'throws when an entry announces a size below 8' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]7).CopyTo($bytes, $daclOffset + 8 + 2)

        { Get-Ace -Descriptor $bytes } | Should -Throw '*size of 7*'
    }

    It 'reads an entry of exactly 8 bytes of another type' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 2; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]8).CopyTo($bytes, $daclOffset + 8 + 2)

        (@(Get-Ace -Descriptor $bytes))[0].Type | Should -BeExactly 'Other'
    }

    It 'reads an 8-byte entry that ends exactly at the end of the descriptor' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 2; Sid = 'S-1-5-18'; Flags = 0 })
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]8).CopyTo($bytes, $daclOffset + 8 + 2)
        [BitConverter]::GetBytes([uint16]16).CopyTo($bytes, $daclOffset + 2)
        $cut = [byte[]]$bytes[0..($daclOffset + 15)]

        $ace = @(Get-Ace -Descriptor $cut)

        $ace.Count | Should -Be 1
        $ace[0].Type | Should -BeExactly 'Other'
    }

    It 'throws when the SID of an object entry lies past the entry size' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(
            @{ Type = 5; Sid = 'S-1-5-18'; ObjectType = $script:memberGuid; Flags = 0 }
            @{ Type = 0; Sid = 'S-1-5-21-1-2-3-1105'; Flags = 0 }
        )
        $daclOffset = [BitConverter]::ToUInt32($bytes, 16)
        [BitConverter]::GetBytes([uint16]28).CopyTo($bytes, $daclOffset + 8 + 2)

        { Get-Ace -Descriptor $bytes } | Should -Throw '*SID of entry 0*'
    }

    It 'reads an entry whose SID header ends exactly at the entry size' {
        $bytes = ConvertTo-BinaryDescriptor -Ace @(@{ Type = 0; Sid = 'S-1-5'; Flags = 0 })

        (@(Get-Ace -Descriptor $bytes))[0].Sid | Should -BeExactly 'S-1-5'
    }
}
