BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:narrowGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'

    function Get-AceFixture {
        param(
            [string] $Sid = 'S-1-5-21-1-2-3-527',
            [uint32] $Mask = 0x30,
            [string] $ObjectType = $script:narrowGuid,
            [string] $Type = 'Allow',
            [bool] $InheritOnly = $false
        )
        [PSCustomObject]@{
            Type = $Type; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $InheritOnly; IsInherited = $false; Sid = $Sid
        }
    }

    function Get-Broad {
        param([object[]] $Ace)
        InModuleScope Maester -Parameters @{ Ace = $Ace } {
            param($Ace)
            Get-MtAnssiAdKeyAdminsBroadAce -Ace $Ace
        }
    }
}

Describe 'Get-MtAnssiAdKeyAdminsBroadAce' {
    It '<Name>' -ForEach @(
        @{ Name = 'accepts the narrow grant on msDS-KeyCredentialLink'; Expected = 0
            Ace = { Get-AceFixture } }
        @{ Name = 'accepts reading every property'; Expected = 0
            Ace = { Get-AceFixture -Mask 0x10 -ObjectType '' } }
        @{ Name = 'accepts list and read-control rights'; Expected = 0
            Ace = { Get-AceFixture -Mask 0x20094 -ObjectType '' } }
        @{ Name = 'flags GenericAll'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x10000000 -ObjectType '' } }
        @{ Name = 'flags the full control mask'; Expected = 1
            Ace = { Get-AceFixture -Mask 0xF01FF -ObjectType '' } }
        @{ Name = 'flags GenericWrite'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x40000000 -ObjectType '' } }
        @{ Name = 'flags writing every property'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x20 -ObjectType '' } }
        @{ Name = 'flags writing another property'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x20 -ObjectType 'bf9679c0-0de6-11d0-a285-00aa003049e2' } }
        @{ Name = 'flags the narrow grant combined with WriteDacl'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x40030 } }
        @{ Name = 'flags WriteOwner'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x80000 -ObjectType '' } }
        @{ Name = 'flags extended rights'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x100 -ObjectType '' } }
        @{ Name = 'flags creating child objects'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x1 -ObjectType '' } }
        @{ Name = 'flags deleting the object'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x10000 -ObjectType '' } }
        @{ Name = 'flags deleting the tree'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x40 -ObjectType '' } }
        @{ Name = 'flags deleting child objects'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x2 -ObjectType '' } }
        @{ Name = 'flags a broad entry that only inherits'; Expected = 1
            Ace = { Get-AceFixture -Mask 0x10000000 -ObjectType '' -InheritOnly $true } }
        @{ Name = 'ignores a deny entry'; Expected = 0
            Ace = { Get-AceFixture -Mask 0x10000000 -ObjectType '' -Type 'Deny' } }
        @{ Name = 'ignores an entry that is neither allow nor deny'; Expected = 0
            Ace = { Get-AceFixture -Mask 0x10000000 -ObjectType '' -Type 'Other' } }
        @{ Name = 'ignores a RID that only starts with 527'; Expected = 0
            Ace = { Get-AceFixture -Sid 'S-1-5-21-1-2-3-5270' -Mask 0x10000000 -ObjectType '' } }
        @{ Name = 'flags Key Admins (526) as well'; Expected = 1
            Ace = { Get-AceFixture -Sid 'S-1-5-21-1-2-3-526' -Mask 0x10000000 -ObjectType '' } }
        @{ Name = 'ignores another group'; Expected = 0
            Ace = { Get-AceFixture -Sid 'S-1-5-21-1-2-3-512' -Mask 0x10000000 -ObjectType '' } }
        @{ Name = 'ignores a custom group whose RID only ends in 527'; Expected = 0
            Ace = { Get-AceFixture -Sid 'S-1-5-21-1-2-3-1527' -Mask 0x10000000 -ObjectType '' } }
    ) {
        $ace = & $Ace

        @(Get-Broad -Ace @($ace)).Count | Should -Be $Expected
    }

    It 'names the group, the mask and the object type of a broad entry' {
        $found = @(Get-Broad -Ace @(
                Get-AceFixture -Sid 'S-1-5-21-1-2-3-527' -Mask 0x10000000 -ObjectType ''
            ))

        $found[0].Group | Should -Be 'Enterprise Key Admins'
        $found[0].Sid | Should -Be 'S-1-5-21-1-2-3-527'
        $found[0].Mask | Should -Be '0x10000000'
        $found[0].ObjectType | Should -Be 'all'
    }

    It 'names Key Admins for the 526 entry' {
        $found = @(Get-Broad -Ace @(
                Get-AceFixture -Sid 'S-1-5-21-1-2-3-526' -Mask 0x10000000 -ObjectType ''
            ))

        $found[0].Group | Should -Be 'Key Admins'
    }

    It 'returns every broad entry and skips the narrow ones' {
        $found = @(Get-Broad -Ace @(
                Get-AceFixture
                Get-AceFixture -Sid 'S-1-5-21-1-2-3-526'
                Get-AceFixture -Sid 'S-1-5-21-1-2-3-527' -Mask 0x10000000 -ObjectType ''
                Get-AceFixture -Sid 'S-1-5-21-1-2-3-526' -Mask 0x40000 -ObjectType ''
            ))

        $found.Count | Should -Be 2
    }

    It 'returns nothing for no entries' {
        @(Get-Broad -Ace @()).Count | Should -Be 0
    }
}
