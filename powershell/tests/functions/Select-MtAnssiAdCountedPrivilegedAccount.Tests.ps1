BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'

    function Get-Account {
        param([string] $Name, [string] $Rid = '1105', [string[]] $Link = @('Member'))
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=contoso,DC=com"
            Link              = $Link
            Item              = [PSCustomObject]@{
                Name = $Name
                Sid  = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
            }
        }
    }

    function Get-Controller {
        param([string] $Dn)
        $computer = [PSCustomObject]@{ DistinguishedName = $Dn }
        [PSCustomObject]@{ Type = 'Writable'; Computer = $computer }
    }

    function Select-Counted {
        param([object[]] $Account, [object[]] $DomainController = @())
        $parameters = @{
            Account = $Account; Controller = $DomainController; Sid = $script:domainSid
        }
        InModuleScope Maester -Parameters $parameters {
            param($Account, $Controller, $Sid)
            @(Select-MtAnssiAdCountedPrivilegedAccount -Account $Account `
                    -DomainController $Controller -DomainSid $Sid)
        }
    }
}

Describe 'Select-MtAnssiAdCountedPrivilegedAccount' {
    It 'keeps members through a group or a primary group' {
        $result = Select-Counted -Account @(
            Get-Account -Name 'alice'
            Get-Account -Name 'bob' -Rid '1106' -Link 'PrimaryGroup'
        )

        @($result | ForEach-Object { $_.Item.Name }) | Should -Be @('alice', 'bob')
    }

    It 'leaves out an account that is privileged only as a protected account' {
        $krbtgt = Get-Account -Name 'krbtgt' -Rid '502' -Link 'ProtectedAccount'
        $result = Select-Counted -Account @($krbtgt)

        $result.Count | Should -Be 0
    }

    It 'keeps a protected account that is also a group member, except the RID 500 account' {
        $result = Select-Counted -Account @(
            Get-Account -Name 'krbtgt' -Rid '502' -Link 'Member', 'ProtectedAccount'
            Get-Account -Name 'Administrator' -Rid '500' -Link 'Member', 'ProtectedAccount'
        )

        @($result | ForEach-Object { $_.Item.Name }) | Should -Be @('krbtgt')
    }

    It 'leaves out domain controller accounts, whatever the case of their name' {
        $result = Select-Counted -Account @(
            Get-Account -Name 'DC1' -Rid '1000' -Link 'PrimaryGroup'
            Get-Account -Name 'alice'
        ) -DomainController @(Get-Controller -Dn 'cn=DC1,dc=contoso,dc=com')

        @($result | ForEach-Object { $_.Item.Name }) | Should -Be @('alice')
    }

    It 'returns nothing for no account' {
        (Select-Counted -Account @()).Count | Should -Be 0
    }
}
