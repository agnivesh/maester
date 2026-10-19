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

    function Use-Ldap {
        param([switch] $Fail)
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRootDse -ModuleName Maester -MockWith {
            [PSCustomObject]@{ ConfigurationNamingContext = 'CN=Configuration,DC=x' }
        }
        if ($Fail) {
            Mock Get-MtLdapDisplaySpecifier -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }
        } else {
            Mock Get-MtLdapDisplaySpecifier -ModuleName Maester -MockWith {
                [PSCustomObject]@{ Name = 'user-Display' }
                [PSCustomObject]@{ Name = 'group-Display' }
            }
        }
    }

    function Get-Specifier {
        param([string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence } {
            param($Evidence)
            @(Get-MtAnssiAdDisplaySpecifier -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdDisplaySpecifier' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'reads the display specifiers of the Configuration partition and disposes the connection' {
        Use-Ldap

        $result = Get-Specifier

        @($result.Name) | Should -Be @('user-Display', 'group-Display')
        Should -Invoke Get-MtLdapDisplaySpecifier -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $ConfigurationNamingContext -eq 'CN=Configuration,DC=x' -and
            $Connection -is [TrackedLdapConnection]
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Get-MtLdapRootDse -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $Connection -is [TrackedLdapConnection] }
        $script:connection.Disposed | Should -Be $true
    }

    It 'reads them once per server for the session' {
        Use-Ldap

        $null = Get-Specifier
        $null = Get-Specifier
        $null = Get-Specifier -Server 'dc2'

        Should -Invoke Get-MtLdapDisplaySpecifier -ModuleName Maester -Times 2 -Exactly
    }

    It 'throws when the read fails, keeps nothing in the cache and disposes the connection' {
        Use-Ldap -Fail

        { Get-Specifier } | Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true

        Use-Ldap
        @(Get-Specifier).Count | Should -Be 2
    }
}
