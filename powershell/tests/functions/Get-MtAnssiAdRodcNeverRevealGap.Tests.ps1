BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:dn = @{
        Admins   = 'CN=Administrators,CN=Builtin,DC=contoso,DC=com'
        Server   = 'CN=Server Operators,CN=Builtin,DC=contoso,DC=com'
        Account  = 'CN=Account Operators,CN=Builtin,DC=contoso,DC=com'
        Backup   = 'CN=Backup Operators,CN=Builtin,DC=contoso,DC=com'
        Denied   = 'CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com'
        Allowed  = 'CN=Allowed RODC Password Replication Group,CN=Users,DC=contoso,DC=com'
    }
    $script:lookup = @{}
    $script:lookup[$script:dn.Admins] = @{ Sid = 'S-1-5-32-544'; Name = 'Administrators' }
    $script:lookup[$script:dn.Server] = @{ Sid = 'S-1-5-32-549'; Name = 'Server Operators' }
    $script:lookup[$script:dn.Account] = @{ Sid = 'S-1-5-32-548'; Name = 'Account Operators' }
    $script:lookup[$script:dn.Backup] = @{ Sid = 'S-1-5-32-551'; Name = 'Backup Operators' }
    $script:lookup[$script:dn.Denied] = @{ Sid = 'S-1-5-21-1-2-3-572'; Name = 'Denied RODC' }
    $script:lookup[$script:dn.Allowed] = @{ Sid = 'S-1-5-21-1-2-3-571'; Name = 'Allowed RODC' }
    $script:default = @($script:dn.Admins, $script:dn.Server, $script:dn.Account, $script:dn.Backup,
        $script:dn.Denied)

    function Get-RodcFixture {
        param([string] $Name = 'RO1', [AllowNull()] [string[]] $Never = $script:default)
        [PSCustomObject]@{
            Type     = 'ReadOnly'
            Computer = [PSCustomObject]@{
                Name              = $Name
                DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
                NeverRevealGroup  = $Never
            }
        }
    }

    function Get-Gap {
        param([AllowNull()] [object[]] $Controller)
        $parameters = @{
            Controller = $Controller; Lookup = $script:lookup; Sid = $script:domainSid
        }
        InModuleScope Maester -Parameters $parameters {
            param($Controller, $Lookup, $Sid)
            Get-MtAnssiAdRodcNeverRevealGap -Controller $Controller -Lookup $Lookup -DomainSid $Sid
        }
    }
}

Describe 'Get-MtAnssiAdRodcNeverRevealGap' {
    It 'returns nothing when the list holds every required group' {
        @(Get-Gap -Controller @(Get-RodcFixture)).Count | Should -Be 0
    }

    It 'accepts extra entries' {
        $never = @($default) + @($dn.Allowed)

        @(Get-Gap -Controller @(Get-RodcFixture -Never $never)).Count | Should -Be 0
    }

    It 'reports <Name> when it is missing' -ForEach @(
        @{ Name = 'Administrators'; Key = 'Admins' }
        @{ Name = 'Server Operators'; Key = 'Server' }
        @{ Name = 'Account Operators'; Key = 'Account' }
        @{ Name = 'Backup Operators'; Key = 'Backup' }
        @{ Name = 'Denied RODC Password Replication Group'; Key = 'Denied' }
    ) {
        $never = @($default | Where-Object { $_ -ne $dn[$Key] })

        $result = @(Get-Gap -Controller @(Get-RodcFixture -Never $never))

        $result.Count | Should -Be 1
        @($result[0].Missing) | Should -Be @($Name)
    }

    It 'reports every group of an empty list, in the documented order' {
        $result = @(Get-Gap -Controller @(Get-RodcFixture -Never @()))

        @($result[0].Missing) -join ',' | Should -BeExactly ('Administrators,Server Operators,' +
            'Account Operators,Backup Operators,Denied RODC Password Replication Group')
    }

    It 'treats a null list as empty' {
        $result = @(Get-Gap -Controller @(Get-RodcFixture -Never $null))

        @($result[0].Missing).Count | Should -Be 5
    }

    It 'accepts a builtin group listed as a foreign security principal' {
        $fsp = 'CN=S-1-5-32-544,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        $never = @($default | Where-Object { $_ -ne $dn.Admins }) + @($fsp)

        @(Get-Gap -Controller @(Get-RodcFixture -Never $never)).Count | Should -Be 0
    }

    It 'requires the denied group of this domain, not of another one' {
        $lookup['CN=Other Denied,DC=other,DC=com'] = @{ Sid = 'S-1-5-21-9-9-9-572'; Name = 'x' }
        $other = 'CN=Other Denied,DC=other,DC=com'
        $never = @($default | Where-Object { $_ -ne $dn.Denied }) + @($other)

        $result = @(Get-Gap -Controller @(Get-RodcFixture -Never $never))

        @($result[0].Missing) | Should -Be @('Denied RODC Password Replication Group')
    }

    It 'returns only the RODCs with a gap, with their name and DN' {
        $result = @(Get-Gap -Controller @(
                (Get-RodcFixture -Name 'GOOD')
                (Get-RodcFixture -Name 'BAD' -Never @($dn.Denied))
            ))

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'BAD'
        $result[0].DistinguishedName | Should -Be 'CN=BAD,OU=Domain Controllers,DC=contoso,DC=com'
    }

    It 'returns nothing for no controller' {
        @(Get-Gap -Controller $null).Count | Should -Be 0
    }
}
