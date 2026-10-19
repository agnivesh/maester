BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    if (-not ('TrackedLdapConnection' -as [type])) {
        Add-Type -ReferencedAssemblies 'System.DirectoryServices.Protocols' -TypeDefinition @'
public class TrackedLdapConnection : System.DirectoryServices.Protocols.LdapConnection {
    public bool Disposed;
    public TrackedLdapConnection() : base("localhost") {}
    protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
}
'@
    }

    $script:psoDn = 'CN=Admins,CN=Password Settings Container,CN=System,DC=x'
    $script:domain = [PSCustomObject]@{ MinPwdLength = 7; MaxPwdAge = $null }

    function Get-Account {
        param([string] $Name)
        [PSCustomObject]@{ DistinguishedName = "CN=$Name,DC=x"; Name = $Name }
    }

    function Use-Ldap {
        param([hashtable] $Resultant = @{}, [switch] $PsoUnreadable, [string] $FailOn = '')
        $script:resultant = $Resultant
        $script:psoUnreadable = [bool]$PsoUnreadable
        $script:failDn = $FailOn
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            if ($SearchBase -eq $script:failDn) { throw 'LDAP search failed' }
            if ($SearchBase -eq $script:psoDn) {
                $length = 15
                if ($script:psoUnreadable) { $length = $null }
                return [PSCustomObject]@{
                    name                         = 'Admins'
                    'msDS-MinimumPasswordLength' = $length
                    'msDS-MaximumPasswordAge'    = [timespan]::FromDays(365)
                }
            }
            [PSCustomObject]@{ 'msDS-ResultantPSO' = $script:resultant[$SearchBase] }
        }
    }

    function Get-Policy {
        param([object[]] $Account)
        $parameters = @{
            Account  = $Account; Domain = $script:domain
            Evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        InModuleScope Maester -Parameters $parameters {
            param($Account, $Domain, $Evidence)
            @(Get-MtAnssiAdEffectivePasswordPolicy -Account $Account -Domain $Domain `
                    -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdEffectivePasswordPolicy' {
    It 'uses the domain policy for an account without a resultant policy' {
        Use-Ldap

        $result = Get-Policy -Account @(Get-Account -Name 'alice')

        $result.Count | Should -Be 1
        $result[0].Account.Name | Should -BeExactly 'alice'
        $result[0].Source | Should -BeExactly 'Domain password policy'
        $result[0].MinLength | Should -Be 7
        @($result[0].Weakness) | Should -Be @('minimum length 7', 'passwords never expire')
    }

    It 'uses the resultant fine-grained policy, read once for several accounts' {
        Use-Ldap -Resultant @{ 'CN=alice,DC=x' = $script:psoDn; 'CN=bob,DC=x' = $script:psoDn }

        $result = Get-Policy -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        @($result.Source) | Should -Be @('Fine-grained policy Admins', 'Fine-grained policy Admins')
        $result[1].MinLength | Should -Be 15
        $result[1].MaxAge | Should -Be ([timespan]::FromDays(365))
        $result[1].Weakness.Count | Should -Be 0
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $SearchBase -eq $script:psoDn }
    }

    It 'reads msDS-ResultantPSO of each account with a base search over one connection' {
        Use-Ldap

        $null = Get-Policy -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=bob,DC=x' -and $Scope -eq 'Base' -and $PageSize -eq 0 -and
            @($Attributes) -join ',' -eq 'msDS-ResultantPSO' -and
            $Connection -is [TrackedLdapConnection]
        }
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when a resultant policy cannot be read, and disposes the connection' {
        Use-Ldap -Resultant @{ 'CN=alice,DC=x' = $script:psoDn } -PsoUnreadable

        { Get-Policy -Account @(Get-Account -Name 'alice') } |
            Should -Throw -ExpectedMessage '*could not be read*'
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when an account read fails' {
        Use-Ldap -FailOn 'CN=alice,DC=x'

        { Get-Policy -Account @(Get-Account -Name 'alice') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'
    }

    It 'returns nothing for no account' {
        Use-Ldap

        (Get-Policy -Account @()).Count | Should -Be 0
    }
}
