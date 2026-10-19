BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'

    function Get-ObjectFixture {
        param([string] $Name, [string] $Rid, [AllowNull()] [object] $PrimaryGroupId = $null)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name              = $Name
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
            PrimaryGroupId    = $PrimaryGroupId
        }
    }

    function Get-Dn {
        param([string] $Name)
        "CN=$Name,DC=contoso,DC=com"
    }

    $script:groups = @(
        Get-ObjectFixture -Name 'Domain Admins' -Rid '512'
        Get-ObjectFixture -Name 'Administrators' -Rid '544'
        Get-ObjectFixture -Name 'Helpdesk' -Rid '1200'
    )

    function Get-Closure {
        param(
            [string[]] $Root = @(),
            [hashtable] $MemberMap = @{},
            [object[]] $User = @(),
            [object[]] $Computer = @()
        )
        $rootGroup = @($script:groups | Where-Object { $_.Name -in $Root })
        $parameters = @{
            Root = $rootGroup; Map = $MemberMap; Sid = $script:domainSid
            User = $User; Computer = $Computer; Group = $script:groups
        }
        InModuleScope Maester -Parameters $parameters {
            param($Root, $Map, $Sid, $User, $Computer, $Group)
            $index = Get-MtAnssiAdDirectoryIndex -User $User -Computer $Computer -Group $Group `
                -DomainSid $Sid
            Resolve-MtAnssiAdPrivilegedClosure -RootGroup $Root -MemberMap $Map -Index $index `
                -DomainSid $Sid
        }
    }
}

Describe 'Resolve-MtAnssiAdPrivilegedClosure' {
    It 'returns each member of the protected groups with its kind and collected item' {
        $alice = Get-ObjectFixture -Name 'alice' -Rid '1105'
        $pc = Get-ObjectFixture -Name 'PC1' -Rid '1106'
        $map = @{ (Get-Dn 'Domain Admins') = @((Get-Dn 'alice'), (Get-Dn 'PC1')) }

        $closure = Get-Closure -Root 'Domain Admins' -MemberMap $map -User @($alice) `
            -Computer @($pc)

        @($closure.Account).Count | Should -Be 2
        $found = @($closure.Account | Where-Object { $_.Kind -eq 'User' })[0]
        $found.DistinguishedName | Should -BeExactly (Get-Dn 'alice')
        $found.Item.Name | Should -BeExactly 'alice'
        @($found.Group) | Should -Be @('Domain Admins')
        @($found.Link) | Should -Be @('Member')
        @($closure.Account | Where-Object { $_.Kind -eq 'Computer' }).Count | Should -Be 1
    }

    It 'returns an account once with every protected group it reaches, sorted' {
        $alice = Get-ObjectFixture -Name 'alice' -Rid '1105'
        $map = @{
            (Get-Dn 'Domain Admins')  = @((Get-Dn 'alice'))
            (Get-Dn 'Administrators') = @((Get-Dn 'Helpdesk'), (Get-Dn 'alice'))
            (Get-Dn 'Helpdesk')       = @((Get-Dn 'alice'))
        }

        $closure = Get-Closure -Root 'Domain Admins', 'Administrators' -MemberMap $map `
            -User @($alice)

        @($closure.Account).Count | Should -Be 1
        @($closure.Account[0].Group) | Should -Be @('Administrators', 'Domain Admins')
        @($closure.Account[0].Link) | Should -Be @('Member')
    }

    It 'keeps every way an account reaches the groups, sorted' {
        $alice = Get-ObjectFixture -Name 'alice' -Rid '1105' -PrimaryGroupId 512
        $map = @{
            (Get-Dn 'Domain Admins')  = @()
            (Get-Dn 'Administrators') = @((Get-Dn 'alice'))
        }

        $closure = Get-Closure -Root 'Domain Admins', 'Administrators' -MemberMap $map `
            -User @($alice)

        @($closure.Account).Count | Should -Be 1
        @($closure.Account[0].Link) | Should -Be @('Member', 'PrimaryGroup')
    }

    It 'adds the built-in Administrator and krbtgt accounts as protected accounts' {
        $users = @(
            Get-ObjectFixture -Name 'Administrator' -Rid '500'
            Get-ObjectFixture -Name 'Guest' -Rid '501'
            Get-ObjectFixture -Name 'krbtgt' -Rid '502'
        )

        $closure = Get-Closure -User $users

        @($closure.Account).Count | Should -Be 2
        $admin = @($closure.Account | Where-Object { $_.Item.Name -eq 'Administrator' })[0]
        @($admin.Group) | Should -Be @('Protected account (RID 500)')
        @($admin.Link) | Should -Be @('ProtectedAccount')
        $krbtgt = @($closure.Account | Where-Object { $_.Item.Name -eq 'krbtgt' })[0]
        @($krbtgt.Group) | Should -Be @('Protected account (RID 502)')
    }

    It 'merges a protected account that is also a group member' {
        $admin = Get-ObjectFixture -Name 'Administrator' -Rid '500'
        $map = @{ (Get-Dn 'Domain Admins') = @((Get-Dn 'Administrator')) }

        $closure = Get-Closure -Root 'Domain Admins' -MemberMap $map -User @($admin)

        @($closure.Account).Count | Should -Be 1
        @($closure.Account[0].Group) | Should -Be @('Domain Admins', 'Protected account (RID 500)')
        @($closure.Account[0].Link) | Should -Be @('Member', 'ProtectedAccount')
    }

    It 'does not treat the members of a group that is not a root as privileged' {
        $alice = Get-ObjectFixture -Name 'alice' -Rid '1105'
        $map = @{
            (Get-Dn 'Domain Admins') = @()
            (Get-Dn 'Helpdesk')      = @((Get-Dn 'alice'))
        }

        $closure = Get-Closure -Root 'Domain Admins' -MemberMap $map -User @($alice)

        @($closure.Account).Count | Should -Be 0
    }

    It 'returns an unresolved member once with every protected group it was found under' {
        $foreign = 'CN=S-1-5-21-9-9-9-519,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        $map = @{
            (Get-Dn 'Domain Admins')  = @($foreign)
            (Get-Dn 'Administrators') = @($foreign)
        }

        $closure = Get-Closure -Root 'Domain Admins', 'Administrators' -MemberMap $map

        @($closure.Unresolved).Count | Should -Be 1
        $closure.Unresolved[0].DistinguishedName | Should -BeExactly $foreign
        @($closure.Unresolved[0].Group) | Should -Be @('Administrators', 'Domain Admins')
        @($closure.Account).Count | Should -Be 0
    }

    It 'names a protected group once for a member found under it through two paths' {
        $foreign = 'CN=S-1-5-21-9-9-9-519,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        $map = @{
            (Get-Dn 'Domain Admins') = @($foreign, (Get-Dn 'Helpdesk'))
            (Get-Dn 'Helpdesk')      = @($foreign)
        }

        $closure = Get-Closure -Root 'Domain Admins' -MemberMap $map

        @($closure.Unresolved).Count | Should -Be 1
        @($closure.Unresolved[0].Group) | Should -Be @('Domain Admins')
    }

    It 'returns empty lists when there is no protected group and no protected account' {
        $closure = Get-Closure

        $null -ne $closure | Should -Be $true
        @($closure.Account).Count | Should -Be 0
        @($closure.Unresolved).Count | Should -Be 0
        @($closure.Group).Count | Should -Be 0
    }

    It 'lists every walked group once, sorted, across the protected groups' {
        $map = @{
            (Get-Dn 'Domain Admins')  = @((Get-Dn 'Helpdesk'))
            (Get-Dn 'Administrators') = @((Get-Dn 'helpdesk'))
            (Get-Dn 'Helpdesk')       = @()
        }

        $closure = Get-Closure -Root 'Domain Admins', 'Administrators' -MemberMap $map

        $expected = @('Administrators', 'Domain Admins', 'Helpdesk') | ForEach-Object { Get-Dn $_ }
        $closure.Group -join ';' | Should -BeExactly ($expected -join ';')
    }

    It 'throws when a nested group was not read' {
        $map = @{ (Get-Dn 'Domain Admins') = @((Get-Dn 'Helpdesk')) }

        { Get-Closure -Root 'Domain Admins' -MemberMap $map } |
            Should -Throw -ExpectedMessage '*Helpdesk*were not read*'
    }
}
