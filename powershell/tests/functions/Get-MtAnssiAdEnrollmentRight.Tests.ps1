BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:autoEnroll = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $script:other = 'bf967950-0de6-11d0-a285-00aa003049e2'

    function Get-AceFixture {
        param(
            [string] $Rid = '1105',
            [uint32] $Mask,
            [string] $ObjectType = '',
            [string] $Type = 'Allow',
            [bool] $InheritOnly = $false,
            [bool] $IsInherited = $false
        )
        [PSCustomObject]@{
            Type = $Type; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $InheritOnly; IsInherited = $IsInherited; Sid = "$script:domainSid-$Rid"
        }
    }

    function Get-TemplateFixture {
        param([string] $Name = 'T', [AllowNull()] [object[]] $Ace, [string] $Owner = '1105')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=Certificate Templates,CN=Public Key Services"
            Name              = $Name
            ObjectClass       = @('top', 'pKICertificateTemplate')
            OwnerSid          = "$script:domainSid-$Owner"
            Ace               = $Ace
        }
    }

    function Get-Right {
        param([object[]] $Object, [string[]] $Trusted = @('S-1-5-18', 'S-1-5-21-1-2-3-512'))
        InModuleScope Maester -Parameters @{ Object = $Object; Trusted = $Trusted } {
            param($Object, $Trusted)
            $set = [System.Collections.Generic.HashSet[string]]::new([string[]]$Trusted)
            @(Get-MtAnssiAdEnrollmentRight -Object $Object -TrustedSid $set)
        }
    }
}

Describe 'Get-MtAnssiAdEnrollmentRight' {
    It 'reports <Want> for mask <Mask> and object type <Type>' -ForEach @(
        @{ Mask = 0x130; Type = 'enroll'; Want = 'Enroll' }
        @{ Mask = 0x100; Type = 'enroll'; Want = 'Enroll' }
        @{ Mask = 0x100; Type = ''; Want = 'AllExtendedRights' }
        @{ Mask = 0x10000000; Type = ''; Want = 'GenericAll' }
        @{ Mask = 0xF01FF; Type = ''; Want = 'GenericAll' }
        @{ Mask = 0x1F01FF; Type = ''; Want = 'GenericAll' }
        @{ Mask = 0x701FF; Type = ''; Want = 'AllExtendedRights' }
    ) {
        $objectType = ''
        if ($Type -eq 'enroll') { $objectType = $script:enroll }
        $ace = Get-AceFixture -Mask $Mask -ObjectType $objectType
        $template = Get-TemplateFixture -Name 'T' -Ace @($ace)

        $rows = Get-Right -Object @($template)

        $rows.Count | Should -Be 1
        $rows[0].Control | Should -BeExactly $Want
        $rows[0].Sid | Should -BeExactly "$script:domainSid-1105"
        $rows[0].Name | Should -BeExactly 'T'
        $rows[0].DistinguishedName | Should -BeExactly (
            'CN=T,CN=Certificate Templates,CN=Public Key Services')
        $rows[0].IsInherited | Should -Be $false
    }

    It 'reports nothing for mask <Mask> and object type <Type>' -ForEach @(
        @{ Mask = 0x100; Type = 'autoEnroll' }
        @{ Mask = 0x130; Type = 'autoEnroll' }
        @{ Mask = 0x100; Type = 'other' }
        @{ Mask = 0x20094; Type = '' }
        @{ Mask = 0x10; Type = '' }
        @{ Mask = 0x20; Type = '' }
        @{ Mask = 0x20; Type = 'enroll' }
        @{ Mask = 0x40000; Type = '' }
        @{ Mask = 0x80000; Type = '' }
        @{ Mask = 0x1; Type = '' }
    ) {
        $objectType = ''
        if ($Type -eq 'enroll') { $objectType = $script:enroll }
        if ($Type -eq 'autoEnroll') { $objectType = $script:autoEnroll }
        if ($Type -eq 'other') { $objectType = $script:other }
        $template = Get-TemplateFixture -Ace @(Get-AceFixture -Mask $Mask -ObjectType $objectType)

        Get-Right -Object @($template) | Should -BeNullOrEmpty
    }

    It 'skips a trusted principal' {
        $ace = @(
            Get-AceFixture -Rid '512' -Mask 0x130 -ObjectType $script:enroll
            Get-AceFixture -Rid '1105' -Mask 0xF01FF
        )

        $rows = Get-Right -Object @(Get-TemplateFixture -Ace $ace)

        @($rows.Sid) | Should -Be @("$script:domainSid-1105")
    }

    It 'treats enrollment by the forest-wide groups of any domain as expected' {
        $ace = @(
            [PSCustomObject]@{
                Type = 'Allow'; Mask = 0x130; ObjectType = $script:enroll
                InheritedObjectType = ''; InheritOnly = $false; IsInherited = $false
                Sid = 'S-1-5-21-9-9-9-519'
            }
        )

        Get-Right -Object @(Get-TemplateFixture -Ace $ace) | Should -BeNullOrEmpty
    }

    It 'skips an entry that only applies to children' {
        $ace = @(Get-AceFixture -Mask 0x130 -ObjectType $script:enroll -InheritOnly $true)

        Get-Right -Object @(Get-TemplateFixture -Ace $ace) | Should -BeNullOrEmpty
    }

    It 'skips a right that an earlier deny entry takes away' {
        $ace = @(
            Get-AceFixture -Mask 0x100 -ObjectType $script:enroll -Type 'Deny'
            Get-AceFixture -Mask 0x130 -ObjectType $script:enroll
        )

        Get-Right -Object @(Get-TemplateFixture -Ace $ace) | Should -BeNullOrEmpty
    }

    It 'keeps a right that only a later deny entry takes away' {
        $ace = @(
            Get-AceFixture -Mask 0x130 -ObjectType $script:enroll
            Get-AceFixture -Mask 0x100 -ObjectType $script:enroll -Type 'Deny'
        )

        (Get-Right -Object @(Get-TemplateFixture -Ace $ace)).Count | Should -Be 1
    }

    It 'does not report the owner, since owning is a right to change the template' {
        $template = Get-TemplateFixture -Ace @() -Owner '1105'

        Get-Right -Object @($template) | Should -BeNullOrEmpty
    }

    It 'reports an inherited entry as inherited' {
        $ace = @(Get-AceFixture -Mask 0x130 -ObjectType $script:enroll -IsInherited $true)

        (Get-Right -Object @(Get-TemplateFixture -Ace $ace))[0].IsInherited | Should -Be $true
    }

    It 'reports each template and each trustee' {
        $first = Get-TemplateFixture -Name 'A' -Ace @(
            Get-AceFixture -Rid '1105' -Mask 0x130 -ObjectType $script:enroll
            Get-AceFixture -Rid '1106' -Mask 0x130 -ObjectType $script:enroll
        )
        $second = Get-TemplateFixture -Name 'B' -Ace @(
            Get-AceFixture -Rid '1105' -Mask 0xF01FF
        )

        $rows = Get-Right -Object @($first, $second)

        @($rows | ForEach-Object { "$($_.Name):$($_.Sid.Split('-')[-1])" }) |
            Should -Be @('A:1105', 'A:1106', 'B:1105')
    }

    It 'throws when the permissions of a template were not read' {
        $template = Get-TemplateFixture -Name 'Unread' -Ace $null

        { Get-Right -Object @($template) } | Should -Throw -ExpectedMessage "*'CN=Unread,*"
    }

    It 'returns nothing for no templates' {
        Get-Right -Object @() | Should -BeNullOrEmpty
    }
}
