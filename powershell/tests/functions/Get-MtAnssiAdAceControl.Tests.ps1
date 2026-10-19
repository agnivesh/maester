BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:user = 'S-1-5-21-1-2-3-1105'
    $script:guid = @{
        Member     = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        Reset      = '00299570-246d-11d0-a768-00aa006e0529'
        Replicate  = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        KeyCred    = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
        Rbcd       = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
        GpLink     = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
        GpPath     = 'f30e3bc1-9ff0-11d1-b603-0000f80367c1'
        Spn        = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        AltId      = '00fbf30c-91fe-11d1-aebc-0000f80367c1'
        PublicInfo = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
        ManagedBy  = '0296c120-40da-11d1-a9c0-0000f80367c1'
        Other      = 'bf967950-0de6-11d0-a285-00aa003049e2'
        Enroll     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        AutoEnroll = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    }

    function Get-AceFixture {
        param(
            [string] $Type = 'Allow',
            [uint32] $Mask,
            [string] $ObjectType = '',
            [string] $Sid = $script:user,
            [bool] $InheritOnly = $false,
            [bool] $IsInherited = $false
        )
        [PSCustomObject]@{
            Type = $Type; Mask = $Mask; ObjectType = $ObjectType; InheritedObjectType = ''
            InheritOnly = $InheritOnly; IsInherited = $IsInherited; Sid = $Sid
        }
    }

    function Get-TargetFixture {
        param(
            [object[]] $Ace = @(),
            [string[]] $Class = @('top', 'user'),
            [string] $Owner = 'S-1-5-21-1-2-3-512',
            [string] $Name = 'target'
        )
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=x"
            Name              = $Name
            ObjectClass       = $Class
            OwnerSid          = $Owner
            Ace               = $Ace
        }
    }

    function Get-Control {
        param(
            [object[]] $Object, [string[]] $Trusted = @('S-1-5-18', 'S-1-5-21-1-2-3-512'),
            [AllowNull()] [object[]] $Rule
        )
        $parameters = @{ Object = $Object; Trusted = $Trusted; Rule = $Rule }
        InModuleScope Maester -Parameters $parameters {
            param($Object, $Trusted, $Rule)
            $set = [System.Collections.Generic.HashSet[string]]::new([string[]]$Trusted)
            $extra = @{}
            if ($null -ne $Rule) { $extra.Rule = $Rule }
            @(Get-MtAnssiAdAceControl -Object $Object -TrustedSid $set @extra)
        }
    }

    function Get-RuleFixture {
        param([string] $Control, [uint32] $Mask, [string] $ObjectType = '*')
        [PSCustomObject]@{
            Control = $Control; Level = 1; Mask = $Mask; ObjectType = $ObjectType
            Class = $null; IgnoreType = $null
        }
    }
}

Describe 'Get-MtAnssiAdAceControl' {
    It 'reports <Want> (level <Level>) for mask <Mask> on <On>' -ForEach @(
        @{ Mask = 0x10000000; Type = ''; On = 'user'; Want = 'GenericAll'; Level = 1 }
        @{ Mask = 0xF01FF; Type = ''; On = 'user'; Want = 'GenericAll'; Level = 1 }
        @{ Mask = 0xF01FE; Type = ''; On = 'user'; Want = 'WriteDacl'; Level = 1 }
        @{ Mask = 0x701FF; Type = ''; On = 'user'; Want = 'WriteDacl'; Level = 1 }
        @{ Mask = 0x40000; Type = ''; On = 'user'; Want = 'WriteDacl'; Level = 1 }
        @{ Mask = 0x80000; Type = ''; On = 'user'; Want = 'WriteOwner'; Level = 1 }
        @{ Mask = 0x40000000; Type = ''; On = 'user'; Want = 'GenericWrite'; Level = 1 }
        @{ Mask = 0x20; Type = ''; On = 'user'; Want = 'GenericWrite'; Level = 1 }
        @{ Mask = 0x100; Type = ''; On = 'user'; Want = 'AllExtendedRights'; Level = 1 }
        @{ Mask = 0x100; Type = 'Reset'; On = 'user'; Want = 'ResetPassword'; Level = 1 }
        @{ Mask = 0x100; Type = 'Replicate'; On = 'domainDNS'; Want = 'Replication'; Level = 1 }
        @{ Mask = 0x20; Type = 'Member'; On = 'group'; Want = 'WriteMember'; Level = 1 }
        @{ Mask = 0x8; Type = 'Member'; On = 'group'; Want = 'WriteMember'; Level = 1 }
        @{ Mask = 0x8; Type = ''; On = 'group'; Want = 'WriteMember'; Level = 1 }
        @{ Mask = 0x8; Type = ''; On = 'user'; Want = 'AllValidatedWrites'; Level = 2 }
        @{ Mask = 0x20; Type = 'KeyCred'; On = 'user'; Want = 'KeyCredentialLink'; Level = 1 }
        @{ Mask = 0x20; Type = 'Rbcd'; On = 'computer'; Want = 'ResourceDelegation'; Level = 1 }
        @{ Mask = 0x20; Type = 'GpLink'; On = 'organizationalUnit'; Want = 'GpLink'; Level = 1 }
        @{
            Mask = 0x20; Type = 'GpPath'; On = 'groupPolicyContainer'
            Want = 'GpoFilePath'; Level = 1
        }
        @{
            Mask = 0x20; Type = 'Other'; On = 'pKICertificateTemplate'
            Want = 'WriteTemplateProperty'; Level = 1
        }
        @{ Mask = 0x20; Type = ''; On = 'pKICertificateTemplate'; Want = 'GenericWrite'; Level = 1 }
        @{ Mask = 0x20; Type = 'Spn'; On = 'user'; Want = 'WriteSpn'; Level = 2 }
        @{ Mask = 0x8; Type = 'Spn'; On = 'computer'; Want = 'WriteSpn'; Level = 2 }
        @{ Mask = 0x20; Type = 'AltId'; On = 'user'; Want = 'WriteAltIdentity'; Level = 2 }
        @{
            Mask = 0x20; Type = 'PublicInfo'; On = 'user'
            Want = 'WritePublicInformation'; Level = 2
        }
        @{ Mask = 0x20; Type = 'ManagedBy'; On = 'computer'; Want = 'WriteManagedBy'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'container'; Want = 'CreateChild'; Level = 2 }
        @{
            Mask = 0x1; Type = 'Other'; On = 'groupPolicyContainer'
            Want = 'CreateChild'; Level = 2
        }
        @{ Mask = 0x1; Type = ''; On = 'domainDNS'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'configuration'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'dMD'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'msDFSR-ReplicationGroup'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'msDFSR-Topology'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'msDFSR-Content'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'msDFSR-LocalSettings'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'msDFSR-Subscriber'; Want = 'CreateChild'; Level = 2 }
        @{ Mask = 0x1; Type = ''; On = 'Container'; Want = 'CreateChild'; Level = 2 }
    ) {
        $objectType = ''
        if ($Type) { $objectType = $script:guid[$Type] }
        $ace = Get-AceFixture -Mask $Mask -ObjectType $objectType
        $object = Get-TargetFixture -Class @('top', $On) -Ace @($ace)

        $rows = Get-Control -Object @($object)

        $rows.Count | Should -Be 1
        $rows[0].Control | Should -BeExactly $Want
        $rows[0].Level | Should -Be $Level
        $rows[0].Sid | Should -BeExactly $script:user
        $rows[0].DistinguishedName | Should -BeExactly 'CN=target,DC=x'
        $rows[0].Name | Should -BeExactly 'target'
        $rows[0].IsInherited | Should -Be $false
    }

    It 'reports nothing for mask <Mask> with object type <Type> on <On>' -ForEach @(
        @{ Mask = 0x1; Type = ''; On = 'organizationalUnit' }
        @{ Mask = 0x1; Type = ''; On = 'user' }
        @{ Mask = 0x20; Type = 'Other'; On = 'user' }
        @{ Mask = 0x100; Type = 'Other'; On = 'user' }
        @{ Mask = 0x8; Type = 'Other'; On = 'group' }
        @{ Mask = 0x20094; Type = ''; On = 'user' }
        @{ Mask = 0x10; Type = ''; On = 'user' }
        @{ Mask = 0x10000; Type = ''; On = 'user' }
        @{ Mask = 0x10; Type = 'Other'; On = 'pKICertificateTemplate' }
        @{ Mask = 0x100; Type = 'Other'; On = 'pKICertificateTemplate' }
        @{ Mask = 0x130; Type = 'Enroll'; On = 'pKICertificateTemplate' }
        @{ Mask = 0x20; Type = 'Enroll'; On = 'pKICertificateTemplate' }
        @{ Mask = 0x130; Type = 'AutoEnroll'; On = 'pKICertificateTemplate' }
        @{ Mask = 0x20; Type = 'AutoEnroll'; On = 'pKICertificateTemplate' }
    ) {
        $objectType = ''
        if ($Type) { $objectType = $script:guid[$Type] }
        $ace = Get-AceFixture -Mask $Mask -ObjectType $objectType
        $object = Get-TargetFixture -Class @('top', $On) -Ace @($ace)

        @(Get-Control -Object @($object)).Count | Should -Be 0
    }

    It 'skips trusted trustees and the forest-wide groups of any domain, not other groups' {
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Mask 0x40000 -Sid 'S-1-5-18'
            Get-AceFixture -Mask 0x40000 -Sid 'S-1-5-21-9-9-9-519'
            Get-AceFixture -Mask 0x40000 -Sid 'S-1-5-21-9-9-9-520'
        )

        $rows = Get-Control -Object @($object)

        @($rows.Sid) -join ',' | Should -BeExactly 'S-1-5-21-9-9-9-520'
    }

    It 'skips inherit-only entries, allow and deny' {
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x40000 -InheritOnly $true
            Get-AceFixture -Mask 0x80000 -InheritOnly $true
            Get-AceFixture -Mask 0x40000
        )

        $rows = Get-Control -Object @($object)

        @($rows.Control) -join ',' | Should -BeExactly 'WriteDacl'
    }

    It 'keeps the inherited flag of the entry' {
        $object = Get-TargetFixture -Ace @(Get-AceFixture -Mask 0x40000 -IsInherited $true)

        (Get-Control -Object @($object))[0].IsInherited | Should -Be $true
    }

    It 'ignores entries of another type' {
        $object = Get-TargetFixture -Ace @(Get-AceFixture -Type 'Other' -Mask 0x40000)

        @(Get-Control -Object @($object)).Count | Should -Be 0
    }

    It 'lets an earlier deny of <Name> cancel the right' -ForEach @(
        @{ Name = 'the same trustee'; Sid = 'S-1-5-21-1-2-3-1105' }
        @{ Name = 'Everyone'; Sid = 'S-1-1-0' }
        @{ Name = 'Authenticated Users'; Sid = 'S-1-5-11' }
    ) {
        $object = Get-TargetFixture -Class @('top', 'group') -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x20 -ObjectType $script:guid.Member -Sid $Sid
            Get-AceFixture -Mask 0x20 -ObjectType $script:guid.Member
        )

        @(Get-Control -Object @($object)).Count | Should -Be 0
    }

    It 'keeps the right when the deny is <Name>' -ForEach @(
        @{
            Name = 'for another trustee'; Sid = 'S-1-5-21-1-2-3-1106'; Mask = 0x20; Type = 'Member'
            After = $false
        }
        @{ Name = 'after the allow'; Sid = 'S-1-1-0'; Mask = 0x20; Type = 'Member'; After = $true }
        @{
            Name = 'for another object type'; Sid = 'S-1-1-0'; Mask = 0x20; Type = 'Other'
            After = $false
        }
        @{ Name = 'for other bits'; Sid = 'S-1-1-0'; Mask = 0x10; Type = 'Member'; After = $false }
    ) {
        $deny = Get-AceFixture -Type 'Deny' -Mask $Mask -ObjectType $script:guid[$Type] -Sid $Sid
        $allow = Get-AceFixture -Mask 0x20 -ObjectType $script:guid.Member
        $ace = @($deny, $allow)
        if ($After) { $ace = @($allow, $deny) }
        $object = Get-TargetFixture -Class @('top', 'group') -Ace $ace

        @((Get-Control -Object @($object)).Control) -join ',' | Should -BeExactly 'WriteMember'
    }

    It 'lets a deny without object type cancel a right on one attribute' {
        $object = Get-TargetFixture -Class @('top', 'group') -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x20 -Sid 'S-1-1-0'
            Get-AceFixture -Mask 0x20 -ObjectType $script:guid.Member
        )

        @(Get-Control -Object @($object)).Count | Should -Be 0
    }

    It 'needs the deny to cover every granted bit of the rule' {
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x10000000 -Sid 'S-1-1-0'
            Get-AceFixture -Mask 0x50000000
        )

        @((Get-Control -Object @($object)).Control) -join ',' | Should -BeExactly 'GenericWrite'
    }

    It 'keeps full control when a deny covers only part of it' {
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x40000 -Sid 'S-1-1-0'
            Get-AceFixture -Mask 0xF01FF
        )

        @((Get-Control -Object @($object)).Control) -join ',' | Should -BeExactly 'GenericAll'
    }

    It 'reports the next right of an entry when a deny cancels the first one' {
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Type 'Deny' -Mask 0x40000 -Sid 'S-1-1-0'
            Get-AceFixture -Mask 0xC0000
        )

        @((Get-Control -Object @($object)).Control) -join ',' | Should -BeExactly 'WriteOwner'
    }

    It 'reports an untrusted owner as a level 1 Owner row before the DACL rows' {
        $ace = Get-AceFixture -Mask 0x40000
        $object = Get-TargetFixture -Owner 'S-1-5-21-1-2-3-1107' -Ace @($ace)

        $rows = Get-Control -Object @($object)

        @($rows.Control) -join ',' | Should -BeExactly 'Owner,WriteDacl'
        $rows[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1107'
        $rows[0].Level | Should -Be 1
        $rows[0].IsInherited | Should -Be $false
        $rows[0].DistinguishedName | Should -BeExactly 'CN=target,DC=x'
        $rows[0].Name | Should -BeExactly 'target'
    }

    It 'reports no Owner row for a trusted or missing owner' -ForEach @(
        @{ Owner = 'S-1-5-21-1-2-3-512' }
        @{ Owner = 'S-1-5-21-9-9-9-519' }
        @{ Owner = '' }
    ) {
        $object = Get-TargetFixture -Owner $Owner -Ace @()

        @(Get-Control -Object @($object)).Count | Should -Be 0
    }

    It 'reports the rows of every object, one row per entry' {
        $firstAce = @(Get-AceFixture -Mask 0x40000; Get-AceFixture -Mask 0x80000)
        $first = Get-TargetFixture -Name 'one' -Ace $firstAce
        $secondAce = @(Get-AceFixture -Mask 0x40000 -Sid 'S-1-5-21-1-2-3-1106')
        $second = Get-TargetFixture -Name 'two' -Ace $secondAce

        $rows = Get-Control -Object @($first, $second)

        @($rows | ForEach-Object { "$($_.Name):$($_.Control):$($_.Sid)" }) -join ';' |
            Should -BeExactly ('one:WriteDacl:S-1-5-21-1-2-3-1105;' +
                'one:WriteOwner:S-1-5-21-1-2-3-1105;two:WriteDacl:S-1-5-21-1-2-3-1106')
    }

    It 'does not run the rules for an entry that holds none of the single rule bits' {
        Mock Select-MtAnssiAdAceControl -ModuleName Maester -MockWith { }
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Mask 0x20094
            Get-AceFixture -Mask 0x10000
            Get-AceFixture -Mask 0x40000
        )

        $null = Get-Control -Object @($object)

        Should -Invoke Select-MtAnssiAdAceControl -ModuleName Maester -Times 1 -Exactly
        Should -Invoke Select-MtAnssiAdAceControl -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $Ace.Mask -eq 0x40000 }
    }

    It 'returns nothing for no objects' {
        @(Get-Control -Object @()).Count | Should -Be 0
    }

    It 'throws for an object whose DACL was not read' {
        $object = Get-TargetFixture
        $object.Ace = $null

        { Get-Control -Object @($object) } | Should -Throw '*CN=target,DC=x*not read*'
    }

    It 'reports the rights of a custom rule table instead of the default one' {
        $rule = @(Get-RuleFixture -Control 'Custom' -Mask 0x100)
        $object = Get-TargetFixture -Ace @(
            Get-AceFixture -Mask 0x100
            Get-AceFixture -Mask 0x40000
        )

        $rows = Get-Control -Object @($object) -Rule $rule

        @($rows.Control) | Should -Be @('Custom')
    }

    It 'still reports an untrusted owner with a custom rule table' {
        $object = Get-TargetFixture -Owner 'S-1-5-21-1-2-3-1105'
        $rule = @(Get-RuleFixture -Control 'Custom' -Mask 0x100)

        $rows = Get-Control -Object @($object) -Rule $rule

        @($rows.Control) | Should -Be @('Owner')
    }

    It 'uses the default rule table when none or an empty one is given' -ForEach @(
        @{ Rule = $null }
        @{ Rule = @() }
    ) {
        $object = Get-TargetFixture -Ace @(Get-AceFixture -Mask 0x40000)

        $rows = Get-Control -Object @($object) -Rule $Rule

        @($rows.Control) | Should -Be @('WriteDacl')
    }
}
