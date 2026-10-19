BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-Extra {
        param([AllowNull()] [string[]] $Member)
        InModuleScope Maester -Parameters @{ Member = $Member } {
            param($Member)
            Get-MtAnssiAdPreWindows2000ExtraMember -Member $Member
        }
    }

    $script:fsp = 'CN={0},CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
}

Describe 'Get-MtAnssiAdPreWindows2000ExtraMember' {
    It 'accepts Authenticated Users as the default member' {
        @(Get-Extra -Member @($fsp -f 'S-1-5-11')).Count | Should -Be 0
    }

    It 'accepts Authenticated Users whatever the case of the name' {
        $dn = 'cn=S-1-5-11,cn=foreignsecurityprincipals,DC=contoso,DC=com'

        @(Get-Extra -Member @($dn)).Count | Should -Be 0
    }

    It 'returns nothing for an empty or null member list' {
        @(Get-Extra -Member @()).Count | Should -Be 0
        @(Get-Extra -Member $null).Count | Should -Be 0
    }

    It 'names Everyone and Anonymous Logon' {
        $result = @(Get-Extra -Member @(($fsp -f 'S-1-1-0'), ($fsp -f 'S-1-5-7')))

        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Sid -eq 'S-1-1-0' }).Identity | Should -Be 'Everyone'
        ($result | Where-Object { $_.Sid -eq 'S-1-5-7' }).Identity | Should -Be 'Anonymous Logon'
    }

    It 'returns another foreign security principal with its SID' {
        $result = @(Get-Extra -Member @($fsp -f 'S-1-5-21-1-2-3-1105'))

        $result.Count | Should -Be 1
        $result[0].Sid | Should -Be 'S-1-5-21-1-2-3-1105'
        $result[0].Identity | Should -Be 'Foreign security principal'
        $result[0].DistinguishedName | Should -Be ($fsp -f 'S-1-5-21-1-2-3-1105')
    }

    It 'returns a domain account without a SID' {
        $dn = 'CN=ADCS1,OU=Servers,DC=contoso,DC=com'

        $result = @(Get-Extra -Member @($dn))

        $result.Count | Should -Be 1
        $result[0].Sid | Should -BeNullOrEmpty
        $result[0].Identity | Should -Be 'Account or group of the domain'
        $result[0].DistinguishedName | Should -Be $dn
    }

    It 'does not treat a non-principal container with a SID name as Authenticated Users' {
        $dn = 'CN=S-1-5-11,CN=Users,DC=contoso,DC=com'

        @(Get-Extra -Member @($dn)).Count | Should -Be 1
    }

    It 'does not treat a DN that only contains the Authenticated Users principal as the default' {
        $dn = 'CN=x,CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'

        @(Get-Extra -Member @($dn)).Count | Should -Be 1
    }

    It 'does not treat a SID that only starts like Authenticated Users as the default' {
        @(Get-Extra -Member @($fsp -f 'S-1-5-110')).Count | Should -Be 1
    }

    It 'keeps every extra member next to the default one' {
        $result = @(Get-Extra -Member @(
                $fsp -f 'S-1-5-11'
                'CN=SRV,DC=contoso,DC=com'
                $fsp -f 'S-1-1-0'
            ))

        $result.Count | Should -Be 2
    }
}
