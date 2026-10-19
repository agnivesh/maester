BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Specifier {
        param([string] $Name = 'user-Display', [string[]] $Admin = @(), [string[]] $Shell = @(),
            [string] $Locale = '409')
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=$Locale,CN=DisplaySpecifiers,CN=Configuration,DC=x"
            Name              = $Name
            AdminContextMenu  = $Admin
            ShellContextMenu  = $Shell
        }
    }

    function Get-Script {
        param([object[]] $Specifier)
        InModuleScope Maester -Parameters @{ Specifier = $Specifier } {
            param($Specifier)
            @(Get-MtAnssiAdDisplaySpecifierScript -DisplaySpecifier $Specifier)
        }
    }
}

Describe 'Get-MtAnssiAdDisplaySpecifierScript' {
    It 'returns a program on a file server with the specifier, locale and attribute' {
        $result = Get-Script -Specifier @(Get-Specifier -Admin '1,&Run,\\fs1\tools\run.vbs')

        $result.Count | Should -Be 1
        $result[0].Specifier | Should -BeExactly 'user-Display (409)'
        $result[0].Attribute | Should -BeExactly 'adminContextMenu'
        $result[0].Command | Should -BeExactly '\\fs1\tools\run.vbs'
        $result[0].Location | Should -BeExactly 'File server'
    }

    It 'marks a program on the <Share> share as SYSVOL' -ForEach @(
        @{ Share = 'SYSVOL' }
        @{ Share = 'netlogon' }
    ) {
        $result = Get-Script -Specifier @(Get-Specifier -Shell "3,&Go,\\contoso.com\$Share\a.cmd")

        $result[0].Location | Should -BeExactly 'SYSVOL'
        $result[0].Attribute | Should -BeExactly 'shellContextMenu'
    }

    It 'leaves out COM class IDs and local programs' {
        $result = Get-Script -Specifier @(Get-Specifier -Admin @(
                '2,{12345678-1234-1234-1234-123456789012}'
                '3,&Notepad,C:\Windows\notepad.exe'
            ))

        $result.Count | Should -Be 0
    }

    It 'keeps commas in the command and trims spaces around it' {
        $result = Get-Script -Specifier @(Get-Specifier -Admin '1,&Run, \\fs1\tools\run.cmd a,b ')

        $result[0].Command | Should -BeExactly '\\fs1\tools\run.cmd a,b'
    }

    It 'returns every entry of every specifier, admin menu first' {
        $result = Get-Script -Specifier @(
            Get-Specifier -Name 'user-Display' -Admin '1,&A,\\fs\a.vbs' -Shell '1,&B,\\fs\b.vbs'
            Get-Specifier -Name 'group-Display' -Locale '40c' -Admin '1,&C,\\fs\c.vbs'
        )

        @($result | ForEach-Object { "$($_.Specifier):$($_.Command)" }) | Should -Be @(
            'user-Display (409):\\fs\a.vbs', 'user-Display (409):\\fs\b.vbs',
            'group-Display (40c):\\fs\c.vbs')
    }

    It 'gives no locale for a specifier outside a locale container' {
        $specifier = [PSCustomObject]@{
            DistinguishedName = 'CN=odd,DC=x'; Name = 'odd'
            AdminContextMenu = @('1,&A,\\fs\a.vbs'); ShellContextMenu = @()
        }

        (Get-Script -Specifier @($specifier))[0].Specifier | Should -BeExactly 'odd'
    }

    It 'returns nothing for no specifier' {
        (Get-Script -Specifier @()).Count | Should -Be 0
    }
}
