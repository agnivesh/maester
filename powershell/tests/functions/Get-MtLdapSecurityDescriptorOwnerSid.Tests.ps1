BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function ConvertTo-SidByte {
        param([long[]] $SubAuthority)
        $data = [System.Collections.Generic.List[byte]]::new()
        $data.Add(1)
        $data.Add([byte]$SubAuthority.Count)
        $data.AddRange([byte[]](0, 0, 0, 0, 0, 5))
        foreach ($value in $SubAuthority) {
            $data.AddRange([BitConverter]::GetBytes([uint32]$value))
        }
        , $data.ToArray()
    }

    function Get-DescriptorByte {
        param(
            [int] $OwnerOffset = 20,
            [byte[]] $Sid = (ConvertTo-SidByte -SubAuthority 21, 1, 2, 3, 512)
        )
        $data = [System.Collections.Generic.List[byte]]::new()
        $data.AddRange([byte[]](1, 0, 4, 128))
        $data.AddRange([BitConverter]::GetBytes([int32]$OwnerOffset))
        $data.AddRange([byte[]](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        $data.AddRange($Sid)
        , $data.ToArray()
    }

    function Get-Owner {
        param([AllowNull()] [object] $Descriptor)
        InModuleScope Maester -Parameters @{ Descriptor = $Descriptor } {
            param($Descriptor)
            Get-MtLdapSecurityDescriptorOwnerSid -Descriptor $Descriptor
        }
    }
}

Describe 'Get-MtLdapSecurityDescriptorOwnerSid' {
    It 'reads the owner SID at the offset given in the descriptor header' {
        Get-Owner -Descriptor (Get-DescriptorByte) | Should -BeExactly 'S-1-5-21-1-2-3-512'
    }

    It 'reads a builtin owner SID' {
        $bytes = Get-DescriptorByte -Sid (ConvertTo-SidByte -SubAuthority 32, 544)

        Get-Owner -Descriptor $bytes | Should -BeExactly 'S-1-5-32-544'
    }

    It 'returns $null for a descriptor without an owner' {
        $null -eq (Get-Owner -Descriptor (Get-DescriptorByte -OwnerOffset 0)) | Should -Be $true
    }

    It 'returns $null for bytes too short to be a descriptor' -ForEach @(
        @{ Length = 5 }
        @{ Length = 19 }
    ) {
        $bytes = [byte[]](Get-DescriptorByte)[0..($Length - 1)]

        $null -eq (Get-Owner -Descriptor $bytes) | Should -Be $true
    }

    It 'reads the owner of a descriptor parsed on Windows' {
        $parsed = [PSCustomObject]@{ Owner = [PSCustomObject]@{ Sid = 'S-1-5-18' } }

        Get-Owner -Descriptor $parsed | Should -BeExactly 'S-1-5-18'
    }

    It 'returns $null without a descriptor' {
        $null -eq (Get-Owner -Descriptor $null) | Should -Be $true
    }

    It 'throws for an owner offset outside the bytes' {
        { Get-Owner -Descriptor (Get-DescriptorByte -OwnerOffset 200) } | Should -Throw
    }
}
