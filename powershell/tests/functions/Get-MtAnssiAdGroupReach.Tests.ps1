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

    function Get-Reach {
        param(
            [string] $Start,
            [hashtable] $MemberMap,
            [object[]] $User = @(),
            [object[]] $Computer = @(),
            [object[]] $Group = @()
        )
        $parameters = @{
            Start = (Get-Dn -Name $Start); Map = $MemberMap; Sid = $script:domainSid
            User = $User; Computer = $Computer; Group = $Group
        }
        InModuleScope Maester -Parameters $parameters {
            param($Start, $Map, $Sid, $User, $Computer, $Group)
            $index = Get-MtAnssiAdDirectoryIndex -User $User -Computer $Computer -Group $Group `
                -DomainSid $Sid
            Get-MtAnssiAdGroupReach -GroupDn $Start -MemberMap $Map -Index $index
        }
    }

    $script:groups = @(
        Get-ObjectFixture -Name 'Root' -Rid '512'
        Get-ObjectFixture -Name 'Mid' -Rid '1200'
        Get-ObjectFixture -Name 'Left' -Rid '1201'
        Get-ObjectFixture -Name 'Right' -Rid '1202'
        Get-ObjectFixture -Name 'Leaf' -Rid '1203'
    )
}

Describe 'Get-MtAnssiAdGroupReach' {
    It 'returns direct user and computer members with the link Member' {
        $users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')
        $computers = @(Get-ObjectFixture -Name 'PC1' -Rid '1106')
        $map = @{ (Get-Dn 'Root') = @((Get-Dn 'alice'), (Get-Dn 'PC1')) }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Computer $computers `
            -Group $groups

        @($reach.Account).Count | Should -Be 2
        $alice = @($reach.Account | Where-Object { $_.Entry.Item.Name -eq 'alice' })[0]
        $alice.Entry.Kind | Should -BeExactly 'User'
        $alice.Link | Should -BeExactly 'Member'
        $pc = @($reach.Account | Where-Object { $_.Entry.Item.Name -eq 'PC1' })[0]
        $pc.Entry.Kind | Should -BeExactly 'Computer'
        @($reach.Unresolved).Count | Should -Be 0
    }

    It 'follows nested groups and does not return the groups themselves' {
        $users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')
        $map = @{
            (Get-Dn 'Root') = @((Get-Dn 'Mid'))
            (Get-Dn 'Mid')  = @((Get-Dn 'Leaf'))
            (Get-Dn 'Leaf') = @((Get-Dn 'alice'))
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Group $groups

        @($reach.Account).Count | Should -Be 1
        $reach.Account[0].Entry.Item.Name | Should -BeExactly 'alice'
        $reach.Account[0].Link | Should -BeExactly 'Member'
    }

    It 'returns every walked group once, the starting group included' {
        $map = @{
            (Get-Dn 'Root') = @((Get-Dn 'Mid'), (Get-Dn 'Left'))
            (Get-Dn 'Mid')  = @((Get-Dn 'Root'), (Get-Dn 'Left'))
            (Get-Dn 'Left') = @()
            (Get-Dn 'Leaf') = @()
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -Group $groups

        @($reach.Group | Sort-Object) -join ';' |
            Should -BeExactly ((@('Left', 'Mid', 'Root') | ForEach-Object { Get-Dn $_ }) -join ';')
    }

    It 'stops at a nesting loop' {
        $users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')
        $map = @{
            (Get-Dn 'Root') = @((Get-Dn 'Mid'))
            (Get-Dn 'Mid')  = @((Get-Dn 'Root'), (Get-Dn 'alice'))
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Group $groups

        @($reach.Account).Count | Should -Be 1
    }

    It 'walks a group reached through two paths only once' {
        $users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')
        $map = @{
            (Get-Dn 'Root')  = @((Get-Dn 'Left'), (Get-Dn 'Right'))
            (Get-Dn 'Left')  = @((Get-Dn 'Leaf'))
            (Get-Dn 'Right') = @((Get-Dn 'Leaf'))
            (Get-Dn 'Leaf')  = @((Get-Dn 'alice'))
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Group $groups

        @($reach.Account).Count | Should -Be 1
    }

    It 'walks a group only once when its name is written in another case' {
        $users = @(Get-ObjectFixture -Name 'alice' -Rid '1105')
        $map = @{
            (Get-Dn 'Root')  = @((Get-Dn 'Left'), (Get-Dn 'Right'))
            (Get-Dn 'Left')  = @((Get-Dn 'Leaf'))
            (Get-Dn 'Right') = @('cn=LEAF,dc=contoso,dc=com')
            (Get-Dn 'Leaf')  = @((Get-Dn 'alice'))
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Group $groups

        @($reach.Account).Count | Should -Be 1
    }

    It 'returns the accounts whose primary group is the group with the link PrimaryGroup' {
        $users = @(
            Get-ObjectFixture -Name 'alice' -Rid '1105' -PrimaryGroupId 512
            Get-ObjectFixture -Name 'bob' -Rid '1106' -PrimaryGroupId 513
        )
        $map = @{ (Get-Dn 'Root') = @() }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -User $users -Group $groups

        @($reach.Account).Count | Should -Be 1
        $reach.Account[0].Entry.Item.Name | Should -BeExactly 'alice'
        $reach.Account[0].Link | Should -BeExactly 'PrimaryGroup'
    }

    It 'returns the accounts whose primary group is a nested group' {
        $computers = @(Get-ObjectFixture -Name 'PC1' -Rid '1106' -PrimaryGroupId 1203)
        $map = @{
            (Get-Dn 'Root') = @((Get-Dn 'Leaf'))
            (Get-Dn 'Leaf') = @()
        }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -Computer $computers -Group $groups

        @($reach.Account).Count | Should -Be 1
        $reach.Account[0].Entry.Kind | Should -BeExactly 'Computer'
        $reach.Account[0].Link | Should -BeExactly 'PrimaryGroup'
    }

    It 'returns a member that is not in the collected data as unresolved' {
        $foreign = 'CN=S-1-5-21-9-9-9-512,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        $map = @{ (Get-Dn 'Root') = @($foreign) }

        $reach = Get-Reach -Start 'Root' -MemberMap $map -Group $groups

        @($reach.Unresolved) | Should -Be @($foreign)
        @($reach.Account).Count | Should -Be 0
    }

    It 'returns empty lists for an empty group' {
        $reach = Get-Reach -Start 'Root' -MemberMap @{ (Get-Dn 'Root') = @() } -Group $groups

        $null -ne $reach | Should -Be $true
        @($reach.Account).Count | Should -Be 0
        @($reach.Unresolved).Count | Should -Be 0
    }

    It 'throws when a nested group has no member list' {
        $map = @{ (Get-Dn 'Root') = @((Get-Dn 'Mid')) }

        { Get-Reach -Start 'Root' -MemberMap $map -Group $groups } |
            Should -Throw -ExpectedMessage "*'CN=Mid,DC=contoso,DC=com' were not read*"
    }
}
