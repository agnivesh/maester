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
            Mock Get-MtLdapDnsZone -ModuleName Maester -MockWith { throw 'LDAP search failed' }
        } else {
            Mock Get-MtLdapDnsZone -ModuleName Maester -MockWith {
                [PSCustomObject]@{ DistinguishedName = 'DC=shared,CN=MicrosoftDNS,DC=x' }
                [PSCustomObject]@{ DistinguishedName = "DC=own,$SearchBase" }
            }
        }
    }

    function Get-Zone {
        param([string[]] $Base, [string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        InModuleScope Maester -Parameters @{ Evidence = $evidence; Base = $Base } {
            param($Evidence, $Base)
            @(Get-MtAnssiAdDnsZone -ProtocolEvidence $Evidence -SearchBase $Base)
        }
    }
}

Describe 'Get-MtAnssiAdDnsZone' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns every zone once across the bases and disposes the connection' {
        Use-Ldap

        $result = Get-Zone -Base @('CN=System,DC=x', 'dc=domaindnszones,DC=x')

        @($result.DistinguishedName) -join ';' |
            Should -BeExactly ('DC=shared,CN=MicrosoftDNS,DC=x;DC=own,CN=System,DC=x;' +
                'DC=own,dc=domaindnszones,DC=x')
        Should -Invoke Get-MtLdapDnsZone -ModuleName Maester -Times 2 -Exactly -ParameterFilter {
            $Connection -is [TrackedLdapConnection]
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        $script:connection.Disposed | Should -Be $true
    }

    It 'treats a zone name in another case as the same zone' {
        Use-Ldap
        Mock Get-MtLdapDnsZone -ModuleName Maester -MockWith {
            [PSCustomObject]@{ DistinguishedName = 'DC=a,DC=x' }
            [PSCustomObject]@{ DistinguishedName = 'dc=A,dc=X' }
        }

        @(Get-Zone -Base @('DC=x')).Count | Should -Be 1
    }

    It 'reads once per server and base list in a session' {
        Use-Ldap
        $null = Get-Zone -Base @('CN=System,DC=x')
        $null = Get-Zone -Base @('CN=System,DC=x')
        $null = Get-Zone -Base @('CN=System,DC=x') -Server 'dc2'
        $null = Get-Zone -Base @('CN=System,DC=x', 'DC=ForestDnsZones,DC=x')

        Should -Invoke Get-MtLdapDnsZone -ModuleName Maester -Times 4 -Exactly
    }

    It 'lets a failed search throw and disposes the connection' {
        Use-Ldap -Fail

        { Get-Zone -Base @('DC=x') } | Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true
    }
}
