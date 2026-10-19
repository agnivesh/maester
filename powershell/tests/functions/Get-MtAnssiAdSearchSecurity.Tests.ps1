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
            Mock Get-MtLdapObjectSecurity -ModuleName Maester -MockWith {
                throw 'LDAP search failed'
            }
        } else {
            Mock Get-MtLdapObjectSecurity -ModuleName Maester -MockWith {
                if ($SearchBase -like 'CN=System,*') {
                    [PSCustomObject]@{ DistinguishedName = "CN=MicrosoftDNS,$SearchBase" }
                }
            }
        }
    }

    function Get-Container {
        param(
            [string[]] $Parent, [string] $Server = 'dc1', [string] $Scope = 'OneLevel',
            [string] $Filter = '(&(objectClass=container)(cn=MicrosoftDNS))',
            [string[]] $Attribute = @()
        )
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        $parameters = @{
            Evidence = $evidence; Parent = $Parent; Scope = $Scope; Filter = $Filter
            Attribute = $Attribute
        }
        InModuleScope Maester -Parameters $parameters {
            param($Evidence, $Parent, $Scope, $Filter, $Attribute)
            @(Get-MtAnssiAdSearchSecurity -ProtocolEvidence $Evidence -SearchBase $Parent `
                    -Scope $Scope -Filter $Filter -Attribute $Attribute)
        }
    }
}

Describe 'Get-MtAnssiAdSearchSecurity' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'returns the containers found below each parent and disposes the connection' {
        Use-Ldap

        $result = Get-Container -Parent @('CN=System,DC=x', 'DC=DomainDnsZones,DC=x')

        @($result.DistinguishedName) -join ';' | Should -BeExactly 'CN=MicrosoftDNS,CN=System,DC=x'
        foreach ($base in 'CN=System,DC=x', 'DC=DomainDnsZones,DC=x') {
            $filter = [scriptblock]::Create(
                "`$SearchBase -eq '$base' -and `$Scope -eq 'OneLevel' -and " +
                "`$Filter -eq '(&(objectClass=container)(cn=MicrosoftDNS))' -and " +
                '$Connection -is [TrackedLdapConnection]')
            Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter $filter
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        $script:connection.Disposed | Should -Be $true
    }

    It 'reads once per server and parent list in a session' {
        Use-Ldap
        $null = Get-Container -Parent @('CN=System,DC=x')
        $null = Get-Container -Parent @('CN=System,DC=x')
        $null = Get-Container -Parent @('CN=System,DC=x') -Server 'dc2'
        $null = Get-Container -Parent @('CN=System,DC=x', 'DC=ForestDnsZones,DC=x')

        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 4 -Exactly
    }

    It 'passes the scope and extra attributes, and keys the cache on scope, filter and attributes' {
        Use-Ldap
        $null = Get-Container -Parent @('CN=System,DC=x') -Scope 'Subtree' -Attribute @('gPLink')
        $null = Get-Container -Parent @('CN=System,DC=x') -Scope 'Subtree' -Attribute @('gPLink')
        $null = Get-Container -Parent @('CN=System,DC=x') -Scope 'OneLevel' -Attribute @('gPLink')
        $null = Get-Container -Parent @('CN=System,DC=x') -Scope 'Subtree'
        $null = Get-Container -Parent @('CN=System,DC=x') -Scope 'Subtree' -Filter '(cn=x)'

        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 4 -Exactly
        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $Scope -eq 'Subtree' -and ($Attribute -join ',') -eq 'gPLink' -and
            $Filter -eq '(&(objectClass=container)(cn=MicrosoftDNS))'
        }
    }

    It 'returns nothing, and caches it, when no parent holds the container' {
        Use-Ldap
        @(Get-Container -Parent @('DC=DomainDnsZones,DC=x')).Count | Should -Be 0
        @(Get-Container -Parent @('DC=DomainDnsZones,DC=x')).Count | Should -Be 0

        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly
    }

    It 'lets a failed search throw and disposes the connection' {
        Use-Ldap -Fail

        { Get-Container -Parent @('CN=System,DC=x') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true
    }
}
