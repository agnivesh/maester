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
            [PSCustomObject]@{ DefaultNamingContext = 'DC=contoso,DC=com' }
        }
        if ($Fail) {
            Mock Get-MtLdapObjectOwner -ModuleName Maester -MockWith { throw 'LDAP search failed' }
        } else {
            Mock Get-MtLdapObjectOwner -ModuleName Maester -MockWith {
                [PSCustomObject]@{ Name = 'alice' }
                [PSCustomObject]@{ Name = 'bob' }
            }
        }
    }

    function Get-Owner {
        param([string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence } {
            param($Evidence)
            @(Get-MtAnssiAdObjectOwner -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdObjectOwner' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'reads the owners of the domain objects and disposes the connection' {
        Use-Ldap

        $result = Get-Owner

        @($result.Name) | Should -Be @('alice', 'bob')
        Should -Invoke Get-MtLdapObjectOwner -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $SearchBase -eq 'DC=contoso,DC=com' -and $Connection -is [TrackedLdapConnection]
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Get-MtLdapRootDse -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $Connection -is [TrackedLdapConnection] }
        $script:connection.Disposed | Should -Be $true
    }

    It 'reads them once per server for the session' {
        Use-Ldap

        $null = Get-Owner
        $null = Get-Owner
        $null = Get-Owner -Server 'dc2'

        Should -Invoke Get-MtLdapObjectOwner -ModuleName Maester -Times 2 -Exactly
    }

    It 'throws when the read fails, keeps nothing in the cache and disposes the connection' {
        Use-Ldap -Fail

        { Get-Owner } | Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true

        Use-Ldap
        @(Get-Owner).Count | Should -Be 2
    }
}
