BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:hosts = @{ 'dc1.contoso.com' = $true; 'DC1' = $true }

    function Select-Spn {
        param([AllowNull()] [string[]] $Spn)
        InModuleScope Maester -Parameters @{ Spn = $Spn; Hosts = $script:hosts } {
            param($Spn, $Hosts)
            Select-MtAnssiAdPrivilegedSpn -ServicePrincipalName $Spn -ControllerHost $Hosts
        }
    }
}

Describe 'Select-MtAnssiAdPrivilegedSpn' {
    It 'keeps <Spn>' -ForEach @(
        @{ Spn = 'cifs/dc1.contoso.com' }
        @{ Spn = 'cifs/DC1' }
        @{ Spn = 'ldap/dc1.contoso.com:389' }
        @{ Spn = 'ldap/dc1.contoso.com/contoso.com' }
        @{ Spn = 'HOST/Dc1.Contoso.Com' }
        @{ Spn = 'krbtgt/CONTOSO.COM' }
        @{ Spn = 'krbtgt/anything' }
    ) {
        @(Select-Spn -Spn @($Spn)) | Should -Be @($Spn)
    }

    It 'drops <Spn>' -ForEach @(
        @{ Spn = 'cifs/app1.contoso.com' }
        @{ Spn = 'cifs/dc10.contoso.com' }
        @{ Spn = 'http/web:8080' }
        @{ Spn = 'krbtgtx/CONTOSO.COM' }
        @{ Spn = 'cifs' }
        @{ Spn = '' }
    ) {
        @(Select-Spn -Spn @($Spn)).Count | Should -Be 0
    }

    It 'keeps only the privileged names, in order' {
        $spns = @('cifs/app1', 'cifs/DC1', 'http/web', 'krbtgt/CONTOSO')

        @(Select-Spn -Spn $spns) -join ',' | Should -BeExactly 'cifs/DC1,krbtgt/CONTOSO'
    }

    It 'returns nothing for no names' {
        @(Select-Spn -Spn $null).Count | Should -Be 0
    }
}
