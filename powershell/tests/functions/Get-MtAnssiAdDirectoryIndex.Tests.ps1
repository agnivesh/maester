BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'

    function Get-ObjectFixture {
        param([string] $Name, [string] $Sid, [AllowNull()] [object] $PrimaryGroupId = $null)
        $item = [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Name              = $Name
            Sid               = [PSCustomObject]@{ Value = $Sid }
        }
        if ($null -ne $PrimaryGroupId) {
            $item | Add-Member -NotePropertyName PrimaryGroupId -NotePropertyValue $PrimaryGroupId
        }
        $item
    }

    function Get-Index {
        param([object[]] $User, [object[]] $Computer, [object[]] $Group)
        $parameters = @{
            User = $User; Computer = $Computer; Group = $Group; Sid = $script:domainSid
        }
        InModuleScope Maester -Parameters $parameters {
            param($User, $Computer, $Group, $Sid)
            Get-MtAnssiAdDirectoryIndex -User $User -Computer $Computer -Group $Group `
                -DomainSid $Sid
        }
    }
}

Describe 'Get-MtAnssiAdDirectoryIndex' {
    It 'indexes users, computers and groups by distinguished name with their kind' {
        $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
        $pc = Get-ObjectFixture -Name 'PC1' -Sid "$domainSid-1106"
        $admins = Get-ObjectFixture -Name 'Admins' -Sid 'S-1-5-32-544'

        $index = Get-Index -User @($alice) -Computer @($pc) -Group @($admins)

        $index.ByDn.Count | Should -Be 3
        $index.ByDn['CN=alice,DC=contoso,DC=com'].Kind | Should -BeExactly 'User'
        $index.ByDn['CN=alice,DC=contoso,DC=com'].Item.Name | Should -BeExactly 'alice'
        $index.ByDn['CN=PC1,DC=contoso,DC=com'].Kind | Should -BeExactly 'Computer'
        $index.ByDn['CN=Admins,DC=contoso,DC=com'].Kind | Should -BeExactly 'Group'
    }

    It 'indexes the objects by SID' {
        $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
        $admins = Get-ObjectFixture -Name 'Admins' -Sid 'S-1-5-32-544'

        $index = Get-Index -User @($alice) -Group @($admins)

        $index.BySid.Count | Should -Be 2
        $index.BySid["$domainSid-1105"].Item.Name | Should -BeExactly 'alice'
        $index.BySid['S-1-5-32-544'].Kind | Should -BeExactly 'Group'
    }

    It 'finds a distinguished name without regard to case' {
        $index = Get-Index -User @(Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105")

        $index.ByDn['cn=ALICE,dc=contoso,dc=com'].Item.Name | Should -BeExactly 'alice'
    }

    It 'lists users and computers under the SID of their primary group' {
        $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105" -PrimaryGroupId 512
        $dc = Get-ObjectFixture -Name 'DC1' -Sid "$domainSid-1000" -PrimaryGroupId 516

        $index = Get-Index -User @($alice) -Computer @($dc)

        $index.ByPrimaryGroup.Count | Should -Be 2
        @($index.ByPrimaryGroup["$domainSid-512"]).Count | Should -Be 1
        @($index.ByPrimaryGroup["$domainSid-512"])[0].Item.Name | Should -BeExactly 'alice'
        @($index.ByPrimaryGroup["$domainSid-516"])[0].Kind | Should -BeExactly 'Computer'
    }

    It 'keeps every account that shares a primary group' {
        $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105" -PrimaryGroupId 513
        $bob = Get-ObjectFixture -Name 'bob' -Sid "$domainSid-1106" -PrimaryGroupId '513'

        $index = Get-Index -User @($alice, $bob)

        $names = @($index.ByPrimaryGroup["$domainSid-513"] | ForEach-Object { $_.Item.Name })
        $names | Should -Be @('alice', 'bob')
    }

    It 'leaves out of the primary group lists an object without a primary group' {
        $alice = Get-ObjectFixture -Name 'alice' -Sid "$domainSid-1105"
        $admins = Get-ObjectFixture -Name 'Admins' -Sid 'S-1-5-32-544'

        $index = Get-Index -User @($alice) -Group @($admins)

        $index.ByPrimaryGroup.Count | Should -Be 0
    }

    It 'returns empty indexes when nothing was collected' {
        $index = Get-Index -User $null -Computer $null -Group $null

        $index.ByDn.Count | Should -Be 0
        $index.BySid.Count | Should -Be 0
        $index.ByPrimaryGroup.Count | Should -Be 0
    }
}
