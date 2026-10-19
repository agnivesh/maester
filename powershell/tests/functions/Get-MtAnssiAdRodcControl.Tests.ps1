BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-ControllerFixture {
        param([string] $Name, [string] $Type, [string] $ManagedBy = '')
        [PSCustomObject]@{
            Type     = $Type
            Computer = [PSCustomObject]@{
                DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=x"
                Name              = $Name
                ManagedBy         = $ManagedBy
            }
        }
    }

    function Get-RowFixture {
        param([string] $Dn, [string] $Control, [int] $Level)
        [PSCustomObject]@{
            DistinguishedName = $Dn; Name = 'n'; Sid = 'S-1-5-21-1-2-3-1201'
            Control = $Control; Level = $Level; IsInherited = $true
        }
    }

    function Get-Control {
        param([object[]] $Controller, [object[]] $Row = @(), [hashtable] $Lookup = @{})
        $parameters = @{ Controller = $Controller; Row = $Row; Lookup = $Lookup }
        InModuleScope Maester -Parameters $parameters {
            param($Controller, $Row, $Lookup)
            $trusted = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]@('S-1-5-21-1-2-3-512'))
            @(Get-MtAnssiAdRodcControl -Controller $Controller -Row $Row -Lookup $Lookup `
                    -TrustedSid $trusted)
        }
    }
}

Describe 'Get-MtAnssiAdRodcControl' {
    It 'raises the right to change the manager to level 1 on an RODC whatever the case' {
        $controllers = @(
            Get-ControllerFixture -Name 'RODC1' -Type 'ReadOnly'
            Get-ControllerFixture -Name 'DC1' -Type 'Writable'
        )
        $rows = @(
            Get-RowFixture -Dn 'cn=rodc1,ou=Domain Controllers,DC=x' -Control 'WriteManagedBy' `
                -Level 2
            Get-RowFixture -Dn 'CN=DC1,OU=Domain Controllers,DC=x' -Control 'WriteManagedBy' `
                -Level 2
            Get-RowFixture -Dn 'CN=RODC1,OU=Domain Controllers,DC=x' -Control 'WriteSpn' -Level 2
        )

        $result = Get-Control -Controller $controllers -Row $rows

        @($result | ForEach-Object { "$($_.Control):$($_.Level)" }) -join ',' |
            Should -BeExactly 'WriteManagedBy:1,WriteManagedBy:2,WriteSpn:2'
        $rows[0].Level | Should -Be 2
        $result[0].IsInherited | Should -Be $true
    }

    It 'adds a ManagedBy row for an untrusted manager, named by SID or by DN' {
        $controllers = @(
            Get-ControllerFixture -Name 'RODC1' -Type 'ReadOnly' -ManagedBy 'CN=Helpdesk,DC=x'
            Get-ControllerFixture -Name 'RODC2' -Type 'ReadOnly' -ManagedBy 'CN=Gone,DC=y'
            Get-ControllerFixture -Name 'RODC3' -Type 'ReadOnly' -ManagedBy 'CN=Domain Admins,DC=x'
            Get-ControllerFixture -Name 'RODC4' -Type 'ReadOnly'
            Get-ControllerFixture -Name 'DC1' -Type 'Writable' -ManagedBy 'CN=Helpdesk,DC=x'
        )
        $lookup = @{
            'CN=Helpdesk,DC=x'      = @{ Sid = 'S-1-5-21-1-2-3-1201'; Name = 'Helpdesk' }
            'CN=Domain Admins,DC=x' = @{ Sid = 'S-1-5-21-1-2-3-512'; Name = 'Domain Admins' }
        }

        $result = Get-Control -Controller $controllers -Lookup $lookup

        @($result | ForEach-Object { "$($_.Name):$($_.Sid)" }) -join ',' |
            Should -BeExactly 'RODC1:S-1-5-21-1-2-3-1201,RODC2:CN=Gone,DC=y'
        $result[0].Control | Should -BeExactly 'ManagedBy'
        $result[0].Level | Should -Be 1
        $result[0].IsInherited | Should -Be $false
        $result[0].DistinguishedName | Should -BeExactly 'CN=RODC1,OU=Domain Controllers,DC=x'
    }
}
