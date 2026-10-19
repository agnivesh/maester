BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ObjectFixture {
        param(
            [string] $Name,
            [AllowNull()] [string] $Sid,
            [string] $Dn = "CN=$Name,DC=contoso,DC=com"
        )
        $sidValue = $null
        if ($Sid) { $sidValue = [PSCustomObject]@{ Value = $Sid } }
        [PSCustomObject]@{ DistinguishedName = $Dn; Name = $Name; Sid = $sidValue }
    }

    function Get-Lookup {
        param([object[]] $User, [object[]] $Computer, [object[]] $Group)
        InModuleScope Maester -Parameters @{ User = $User; Computer = $Computer; Group = $Group } {
            param($User, $Computer, $Group)
            Get-MtAnssiAdSidByDn -User $User -Computer $Computer -Group $Group
        }
    }
}

Describe 'Get-MtAnssiAdSidByDn' {
    It 'maps the distinguished names of users, computers and groups to SID and name' {
        $lookup = Get-Lookup -User @(Get-ObjectFixture -Name 'alice' -Sid 'S-1-5-21-1-2-3-1105') `
            -Computer @(Get-ObjectFixture -Name 'PC1' -Sid 'S-1-5-21-1-2-3-1106') `
            -Group @(Get-ObjectFixture -Name 'Admins' -Sid 'S-1-5-32-544')

        $lookup.Count | Should -Be 3
        $lookup['CN=alice,DC=contoso,DC=com'].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1105'
        $lookup['CN=PC1,DC=contoso,DC=com'].Name | Should -BeExactly 'PC1'
        $lookup['CN=Admins,DC=contoso,DC=com'].Sid | Should -BeExactly 'S-1-5-32-544'
    }

    It 'finds a name without regard to case' {
        $lookup = Get-Lookup -Group @(Get-ObjectFixture -Name 'Admins' -Sid 'S-1-5-32-544')

        $lookup['cn=admins,dc=contoso,dc=com'].Sid | Should -BeExactly 'S-1-5-32-544'
    }

    It 'leaves out objects without a SID or a distinguished name' {
        $lookup = Get-Lookup -User @(
            (Get-ObjectFixture -Name 'nosid' -Sid $null)
            (Get-ObjectFixture -Name 'nodn' -Sid 'S-1-5-21-9' -Dn '')
        )

        $lookup.Count | Should -Be 0
    }

    It 'returns an empty lookup for null input' {
        (Get-Lookup -User $null -Computer $null -Group $null).Count | Should -Be 0
    }
}
