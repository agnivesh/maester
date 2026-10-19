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
        if ($Fail) {
            Mock Get-MtLdapCaCertificate -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }
        } else {
            Mock Get-MtLdapCaCertificate -ModuleName Maester -MockWith {
                [PSCustomObject]@{ DistinguishedName = "CN=Root CA,CN=AIA,$SearchBase" }
                [PSCustomObject]@{ DistinguishedName = "CN=NTAuthCertificates,$SearchBase" }
            }
        }
    }

    function Get-Store {
        param([string] $Base = 'CN=Services,CN=Configuration,DC=x', [string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence; Base = $Base } {
            param($Evidence, $Base)
            @(Get-MtAnssiAdCaCertificate -ProtocolEvidence $Evidence -SearchBase $Base)
        }
    }
}

Describe 'Get-MtAnssiAdCaCertificate' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns the objects found below the base and disposes the connection' {
        Use-Ldap

        $result = Get-Store

        @($result.DistinguishedName) -join ';' |
            Should -BeExactly ('CN=Root CA,CN=AIA,CN=Services,CN=Configuration,DC=x;' +
                'CN=NTAuthCertificates,CN=Services,CN=Configuration,DC=x')
        Should -Invoke Get-MtLdapCaCertificate -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $Connection -is [TrackedLdapConnection] -and
            $SearchBase -eq 'CN=Services,CN=Configuration,DC=x'
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        $script:connection.Disposed | Should -Be $true
    }

    It 'returns an empty list when nothing is found' {
        Use-Ldap
        Mock Get-MtLdapCaCertificate -ModuleName Maester -MockWith { }

        @(Get-Store).Count | Should -Be 0
    }

    It 'reads once per server and base in a session' {
        Use-Ldap
        $null = Get-Store
        $null = Get-Store
        $null = Get-Store -Server 'dc2'
        $null = Get-Store -Base 'CN=Services,CN=Configuration,DC=y'

        Should -Invoke Get-MtLdapCaCertificate -ModuleName Maester -Times 3 -Exactly
    }

    It 'lets a failed search throw, disposes the connection and caches nothing' {
        Use-Ldap -Fail

        { Get-Store } | Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true

        Use-Ldap
        @(Get-Store).Count | Should -Be 2
    }
}
