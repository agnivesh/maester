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
        param(
            [string[]] $Context = @(),
            [string] $Schema = 'CN=Schema,CN=Configuration,DC=root,DC=com'
        )
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        $rootDse = [PSCustomObject]@{
            DefaultNamingContext       = 'DC=child,DC=root,DC=com'
            RootDomainNamingContext    = 'DC=root,DC=com'
            ConfigurationNamingContext = 'CN=Configuration,DC=root,DC=com'
            SchemaNamingContext        = $Schema
            NamingContexts             = $Context
        }
        Mock Get-MtLdapRootDse -ModuleName Maester -MockWith ({ $rootDse }.GetNewClosure())
    }

    function Get-Head {
        param([string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence } {
            param($Evidence)
            @(Get-MtAnssiAdNamingContextHead -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdNamingContextHead' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns the naming contexts and the listed DNS partitions, then disposes the connection' {
        Use-Ldap -Context @(
            'dc=domaindnszones,DC=child,DC=root,DC=com'
            'DC=ForestDnsZones,DC=root,DC=com'
            'DC=DomainDnsZones,DC=other,DC=com'
        )

        $result = Get-Head

        $result -join ';' | Should -BeExactly ('DC=child,DC=root,DC=com;' +
            'CN=Configuration,DC=root,DC=com;CN=Schema,CN=Configuration,DC=root,DC=com;' +
            'DC=DomainDnsZones,DC=child,DC=root,DC=com;DC=ForestDnsZones,DC=root,DC=com')
        Should -Invoke Get-MtLdapRootDse -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $Connection -is [TrackedLdapConnection] }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        $script:connection.Disposed | Should -Be $true
    }

    It 'leaves out the DNS partitions the controller does not list' {
        Use-Ldap -Context @('DC=child,DC=root,DC=com')

        (Get-Head).Count | Should -Be 3
    }

    It 'reads the RootDSE once per server in a session' {
        Use-Ldap
        $null = Get-Head
        $null = Get-Head
        $null = Get-Head -Server 'dc2'

        Should -Invoke Get-MtLdapRootDse -ModuleName Maester -Times 2 -Exactly
    }

    It 'throws when a naming context is missing, and caches nothing' {
        Use-Ldap -Schema ''

        { Get-Head } | Should -Throw '*does not name*'
        { Get-Head } | Should -Throw '*does not name*'
    }

    It 'lets a failed RootDSE read throw and disposes the connection' {
        Use-Ldap
        Mock Get-MtLdapRootDse -ModuleName Maester -MockWith { throw 'RootDSE failed' }

        { Get-Head } | Should -Throw -ExpectedMessage 'RootDSE failed'
        $script:connection.Disposed | Should -Be $true
    }
}
