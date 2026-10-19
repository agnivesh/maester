BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:adminsDn = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com'
    $script:lookup = @{}
    $script:lookup[$script:adminsDn] = @{ Sid = 'S-1-5-21-1-2-3-512'; Name = 'Domain Admins' }
    $script:appDn = 'CN=App,OU=Groups,DC=contoso,DC=com'
    $script:lookup[$script:appDn] = @{ Sid = 'S-1-5-21-1-2-3-1201'; Name = 'App' }

    function Invoke-Resolve {
        param([AllowNull()] [string[]] $Dn)
        InModuleScope Maester -Parameters @{ Dn = $Dn; Lookup = $script:lookup } {
            param($Dn, $Lookup)
            Resolve-MtAnssiAdSid -DistinguishedName $Dn -Lookup $Lookup
        }
    }
}

Describe 'Resolve-MtAnssiAdSid' {
    It 'resolves a collected object to its SID, name and RID' {
        $result = @(Invoke-Resolve -Dn @($adminsDn))

        $result[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-512'
        $result[0].Name | Should -BeExactly 'Domain Admins'
        $result[0].Rid | Should -Be 512
        $result[0].DistinguishedName | Should -BeExactly $adminsDn
    }

    It 'resolves a foreign security principal from its name' {
        $dn = 'CN=S-1-5-32-544,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        $result = @(Invoke-Resolve -Dn @($dn))

        $result[0].Sid | Should -BeExactly 'S-1-5-32-544'
        $result[0].Name | Should -BeExactly 'S-1-5-32-544'
        $result[0].Rid | Should -Be 544
    }

    It 'matches the foreign security principal container without regard to case' {
        $dn = 'cn=S-1-1-0,cn=foreignsecurityprincipals,dc=contoso,dc=com'
        $result = @(Invoke-Resolve -Dn @($dn))

        $result[0].Sid | Should -BeExactly 'S-1-1-0'
        $result[0].Rid | Should -Be 0
    }

    It 'leaves a name outside the collected data without SID' {
        $dn = 'CN=Enterprise Admins,CN=Users,DC=root,DC=com'

        $result = @(Invoke-Resolve -Dn @($dn))

        $null -eq $result[0].Sid | Should -Be $true
        $null -eq $result[0].Rid | Should -Be $true
        $result[0].Name | Should -BeExactly $dn
    }

    It 'does not take a SID from a principal name that is not the first part of the DN' {
        $dn = 'CN=x,CN=S-1-5-32-544,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'

        $result = @(Invoke-Resolve -Dn @($dn))

        $null -eq $result[0].Sid | Should -Be $true
    }

    It 'does not take a SID from a name outside the foreign security principals' {
        $result = @(Invoke-Resolve -Dn @('CN=S-1-5-32-544,CN=Users,DC=contoso,DC=com'))

        $null -eq $result[0].Sid | Should -Be $true
    }

    It 'resolves several names in order' {
        $result = @(Invoke-Resolve -Dn @(
                'CN=App,OU=Groups,DC=contoso,DC=com'
                'CN=Domain Admins,CN=Users,DC=contoso,DC=com'
            ))

        ($result | ForEach-Object { $_.Rid }) -join ',' | Should -Be '1201,512'
    }

    It 'returns nothing for null or empty input' {
        @(Invoke-Resolve -Dn $null).Count | Should -Be 0
        @(Invoke-Resolve -Dn @()).Count | Should -Be 0
    }
}
