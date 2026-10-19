BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function ConvertTo-PropertyValue {
        param([uint32] $Id, [byte[]] $Data)
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.AddRange([BitConverter]::GetBytes([uint32]$Data.Length))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]1))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]0))
        $bytes.AddRange([BitConverter]::GetBytes([uint32]1))
        $bytes.AddRange([BitConverter]::GetBytes($Id))
        $bytes.AddRange($Data)
        $bytes.Add(0)
        , $bytes.ToArray()
    }

    function Get-ZoneFixture {
        param([string] $Name, [AllowNull()] [object] $AllowUpdate, [switch] $Empty)
        $property = @(, (ConvertTo-PropertyValue -Id 1 -Data ([byte[]](1, 0, 0, 0))))
        if ($null -ne $AllowUpdate) {
            $property += , (ConvertTo-PropertyValue -Id 2 -Data ([byte[]]@([byte]$AllowUpdate)))
        }
        if ($Empty) { $property += , (ConvertTo-PropertyValue -Id 2 -Data ([byte[]]@())) }
        [PSCustomObject]@{
            DistinguishedName = "DC=$Name,CN=MicrosoftDNS,DC=DomainDnsZones,DC=x"
            Name              = $Name
            Property          = $property
        }
    }

    function Get-Finding {
        param([object[]] $Zone)
        InModuleScope Maester -Parameters @{ Zone = $Zone } {
            param($Zone)
            @(Get-MtAnssiAdDnsZoneFinding -Zone $Zone -DnsRoot 'child.contoso.com' `
                -Forest 'contoso.com')
        }
    }
}

Describe 'Get-MtAnssiAdDnsZoneFinding' {
    It 'reports zones with nonsecure updates, level 1 for the domain and forest _msdcs zones' {
        $zones = @(
            Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate 1
            Get-ZoneFixture -Name '_msdcs.contoso.com' -AllowUpdate 1
            Get-ZoneFixture -Name 'CHILD.contoso.com' -AllowUpdate 1
            Get-ZoneFixture -Name '_msdcs.child.contoso.com' -AllowUpdate 1
            Get-ZoneFixture -Name 'b.contoso.com' -AllowUpdate 1
        )

        $result = Get-Finding -Zone $zones

        @($result | ForEach-Object { "$($_.Name):$($_.Level)" }) -join ';' | Should -BeExactly (
            '_msdcs.contoso.com:1;CHILD.contoso.com:1;_msdcs.child.contoso.com:3;' +
            'apps.contoso.com:3;' +
            'b.contoso.com:3')
        $result[0].DistinguishedName |
            Should -BeExactly 'DC=_msdcs.contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=x'
    }

    It 'ignores zones with update setting <Setting>' -ForEach @(
        @{ Setting = 'none'; Value = 0 }
        @{ Setting = 'secure only'; Value = 2 }
        @{ Setting = 'missing'; Value = $null }
    ) {
        @(Get-Finding -Zone @(Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate $Value)).Count |
            Should -Be 0
    }

    It 'ignores a property without data and values shorter than the header' {
        $zone = Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate $null -Empty
        $zone.Property += , ([byte[]](1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0))

        @(Get-Finding -Zone @($zone)).Count | Should -Be 0
    }

    It 'skips a short value and reads the next allow-update property' {
        $zone = Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate $null
        $zone.Property += , ([byte[]](1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0))
        $zone.Property += , (ConvertTo-PropertyValue -Id 2 -Data ([byte[]]@(1)))

        @(Get-Finding -Zone @($zone)).Count | Should -Be 1
    }

    It 'uses the default, not the following byte, when the property holds no data' {
        $zone = Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate $null
        $empty = [byte[]](0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0)
        $zone.Property += , ([byte[]]($empty + [byte]1))

        @(Get-Finding -Zone @($zone)).Count | Should -Be 0
    }

    It 'reads a header of exactly 21 bytes' {
        $zone = Get-ZoneFixture -Name 'apps.contoso.com' -AllowUpdate $null
        $header = [byte[]](1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0)
        $zone.Property += , ([byte[]]($header + [byte]1))

        @(Get-Finding -Zone @($zone)).Count | Should -Be 1
    }

    It 'leaves out zones whose name starts with two dots' {
        @(Get-Finding -Zone @(Get-ZoneFixture -Name '..Deleted-old.contoso.com' `
            -AllowUpdate 1)).Count |
            Should -Be 0
    }

    It 'returns nothing for no zone' {
        @(Get-Finding -Zone @()).Count | Should -Be 0
    }
}
