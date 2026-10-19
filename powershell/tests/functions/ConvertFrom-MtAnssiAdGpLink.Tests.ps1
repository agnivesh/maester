BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Link {
        param([AllowNull()] [string] $Value)
        InModuleScope Maester -Parameters @{ Value = $Value } {
            param($Value)
            @(ConvertFrom-MtAnssiAdGpLink -Value $Value)
        }
    }
}

Describe 'ConvertFrom-MtAnssiAdGpLink' {
    It ('reads the GPO and the option bits: options <Option> give disabled <Disabled>, enforced' +
        ' <Enforced>') -ForEach @(
        @{ Option = '0'; Disabled = $false; Enforced = $false }
        @{ Option = '1'; Disabled = $true; Enforced = $false }
        @{ Option = '2'; Disabled = $false; Enforced = $true }
        @{ Option = '3'; Disabled = $true; Enforced = $true }
        @{ Option = '4'; Disabled = $false; Enforced = $false }
        @{ Option = '10'; Disabled = $false; Enforced = $true }
        @{ Option = '07'; Disabled = $true; Enforced = $true }
    ) {
        $link = Get-Link -Value "[LDAP://cn={A},cn=policies,cn=system,DC=x;$Option]"

        $link.Count | Should -Be 1
        $link[0].Gpo | Should -BeExactly 'cn={A},cn=policies,cn=system,DC=x'
        $link[0].Disabled | Should -Be $Disabled
        $link[0].Enforced | Should -Be $Enforced
    }

    It 'reads the option bits of a number longer than 32 bits: <Name>' -ForEach @(
        @{ Name = '99999999999'; Option = '99999999999' }
        @{ Name = '2147483648'; Option = '2147483648' }
        @{ Name = '4294967297'; Option = '4294967297' }
        @{ Name = '4294967298'; Option = '4294967298' }
        @{ Name = '400 digits'; Option = ('9' * 400) }
        @{ Name = '1 and 60 zeros'; Option = ('1' + '0' * 60) }
        @{ Name = '2 and 60 zeros'; Option = ('2' + '0' * 60) }
        @{ Name = '1 and 59 zeros and 2'; Option = ('1' + '0' * 59 + '2') }
    ) {
        $number = [System.Numerics.BigInteger]::Parse($Option)

        $link = Get-Link -Value "[LDAP://a;$Option]"

        $link.Count | Should -Be 1
        $link[0].Disabled | Should -Be (-not ($number -band 1).IsZero)
        $link[0].Enforced | Should -Be (-not ($number -band 2).IsZero)
    }

    It 'returns the entries in order, whatever the case of LDAP' {
        $link = Get-Link -Value '[ldap://first;0][LDAP://second;1][Ldap://third;2]'

        ($link.Gpo -join ',') | Should -BeExactly 'first,second,third'
        ($link.Disabled -join ',') | Should -BeExactly 'False,True,False'
    }

    It 'ignores text that is not a link entry: <Name>' -ForEach @(
        @{ Name = 'null'; Value = $null }
        @{ Name = 'empty'; Value = '' }
        @{ Name = 'no options'; Value = '[LDAP://a]' }
        @{ Name = 'a negative number'; Value = '[LDAP://a;-1]' }
        @{ Name = 'no GPO'; Value = '[LDAP://;1]' }
        @{ Name = 'unterminated'; Value = '[LDAP://a;1' }
        @{ Name = 'other text'; Value = 'abc' }
    ) {
        (Get-Link -Value $Value).Count | Should -Be 0
    }

    It 'keeps the valid entries around invalid text' {
        $link = Get-Link -Value 'x[LDAP://a;1]y[LDAP://b]z[LDAP://c;2]'

        ($link.Gpo -join ',') | Should -BeExactly 'a,c'
    }

    It 'reads many entries' {
        (Get-Link -Value ('[LDAP://a;1]' * 2000)).Count | Should -Be 2000
    }
}
