BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:controllers = @(
        [PSCustomObject]@{
            Type     = 'Writable'
            Computer = [PSCustomObject]@{ Name = 'DC1'; DnsHostName = 'dc1.contoso.com' }
        }
        [PSCustomObject]@{
            Type     = 'ReadOnly'
            Computer = [PSCustomObject]@{ Name = 'RO1'; DnsHostName = 'ro1.contoso.com' }
        }
    )

    function Get-AccountFixture {
        param(
            [string] $Name = 'svc',
            [string[]] $Target = @(),
            [bool] $Transition = $false,
            [object] $Enabled = $true
        )
        [PSCustomObject]@{
            DistinguishedName          = "CN=$Name,OU=Service,DC=contoso,DC=com"
            Name                       = $Name
            Enabled                    = $Enabled
            TrustedToAuthForDelegation = $Transition
            AllowedToDelegateTo        = $Target
        }
    }

    function Get-Delegation {
        param([object[]] $User = @(), [object[]] $Computer = @())
        $parameters = @{ User = $User; Computer = $Computer; Controller = $script:controllers }
        InModuleScope Maester -Parameters $parameters {
            param($User, $Computer, $Controller)
            Get-MtAnssiAdPrivilegedDelegation -User $User -Computer $Computer `
                -Controller $Controller
        }
    }
}

Describe 'Get-MtAnssiAdPrivilegedDelegation' {
    Context 'privileged targets' {
        It 'finds a service on a domain controller named by <Name>' -ForEach @(
            @{ Name = 'DNS name'; Spn = 'cifs/dc1.contoso.com' }
            @{ Name = 'short name'; Spn = 'cifs/DC1' }
            @{ Name = 'DNS name with a port'; Spn = 'ldap/dc1.contoso.com:389' }
            @{ Name = 'DNS name with a service name'; Spn = 'ldap/dc1.contoso.com/contoso.com' }
            @{ Name = 'other case'; Spn = 'CIFS/DC1.CONTOSO.COM' }
            @{ Name = 'read-only controller'; Spn = 'HOST/ro1.contoso.com' }
        ) {
            $result = @(Get-Delegation -User @(Get-AccountFixture -Target @($Spn)))

            $result.Count | Should -Be 1
            @($result[0].Target) | Should -Be @($Spn)
        }

        It 'finds the krbtgt service' {
            $result = @(Get-Delegation -User @(Get-AccountFixture -Target @('krbtgt/CONTOSO.COM')))

            @($result[0].Target) | Should -Be @('krbtgt/CONTOSO.COM')
        }

        It 'ignores services on other servers' {
            $target = @('cifs/app1.contoso.com', 'http/web.contoso.com', 'cifs/dc10.contoso.com')

            @(Get-Delegation -User @(Get-AccountFixture -Target $target)).Count | Should -Be 0
        }

        It 'keeps only the privileged targets of an account' {
            $target = @('cifs/app1.contoso.com', 'cifs/dc1.contoso.com', 'http/web')

            $result = @(Get-Delegation -User @(Get-AccountFixture -Target $target))

            @($result[0].Target) | Should -Be @('cifs/dc1.contoso.com')
        }

        It 'does not take an empty host for a controller without DNS name' {
            $controllers = @([PSCustomObject]@{
                    Type     = 'Writable'
                    Computer = [PSCustomObject]@{ Name = 'DC2'; DnsHostName = $null }
                })
            $user = Get-AccountFixture -Target @('cifs/')
            $parameters = @{ User = @($user); Controller = $controllers }

            $result = InModuleScope Maester -Parameters $parameters {
                param($User, $Controller)
                Get-MtAnssiAdPrivilegedDelegation -User $User -Controller $Controller
            }

            @($result).Count | Should -Be 0
        }

        It 'ignores a malformed target without a host part' {
            @(Get-Delegation -User @(Get-AccountFixture -Target @('cifs'))).Count | Should -Be 0
        }
    }

    Context 'accounts' {
        It 'reports protocol transition' {
            $result = @(Get-Delegation -User @(
                    (Get-AccountFixture -Name 'plain' -Target @('cifs/DC1'))
                    (Get-AccountFixture -Name 'pt' -Target @('cifs/DC1') -Transition $true)
                ))

            ($result | Where-Object { $_.Name -eq 'plain' }).ProtocolTransition | Should -Be $false
            ($result | Where-Object { $_.Name -eq 'pt' }).ProtocolTransition | Should -Be $true
        }

        It 'labels users and computers' {
            $result = @(Get-Delegation -User @(Get-AccountFixture -Name 'u' -Target @('cifs/DC1')) `
                    -Computer @(Get-AccountFixture -Name 'c' -Target @('cifs/DC1')))

            ($result | Where-Object { $_.Name -eq 'u' }).Kind | Should -Be 'User'
            ($result | Where-Object { $_.Name -eq 'c' }).Kind | Should -Be 'Computer'
        }

        It 'skips disabled accounts and accounts with an unknown state' {
            $result = @(Get-Delegation -User @(
                    (Get-AccountFixture -Name 'off' -Target @('cifs/DC1') -Enabled $false)
                    (Get-AccountFixture -Name 'unknown' -Target @('cifs/DC1') -Enabled $null)
                ))

            $result.Count | Should -Be 0
        }

        It 'skips accounts without targets' {
            @(Get-Delegation -User @(Get-AccountFixture)).Count | Should -Be 0
        }

        It 'returns the name and DN of the account' {
            $computer = Get-AccountFixture -Name 'APP1$' -Target @('cifs/DC1')
            $result = @(Get-Delegation -Computer @($computer))

            $result[0].Name | Should -Be 'APP1$'
            $result[0].DistinguishedName | Should -Be 'CN=APP1$,OU=Service,DC=contoso,DC=com'
        }

        It 'returns nothing without accounts' {
            @(Get-Delegation).Count | Should -Be 0
        }
    }
}
