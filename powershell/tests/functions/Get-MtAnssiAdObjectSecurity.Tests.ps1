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
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapObjectSecurity -ModuleName Maester -MockWith {
            if ($SearchBase -like 'CN=missing*') { return }
            if ($SearchBase -like 'CN=fail*') { throw 'LDAP search failed' }
            [PSCustomObject]@{ DistinguishedName = $SearchBase; Attribute = $Attribute -join ',' }
        }
    }

    function Get-Security {
        param([string[]] $Name, [string[]] $Attribute = @(), [string] $Server = 'dc1')
        $evidence = [PSCustomObject]@{ ResolvedServer = $Server }
        $parameters = @{ Evidence = $evidence; Name = $Name; Attribute = $Attribute }
        InModuleScope Maester -Parameters $parameters {
            param($Evidence, $Name, $Attribute)
            @(Get-MtAnssiAdObjectSecurity -ProtocolEvidence $Evidence -DistinguishedName $Name `
                    -Attribute $Attribute)
        }
    }
}

Describe 'Get-MtAnssiAdObjectSecurity' {
    BeforeEach {
        Clear-MtADCache
    }

    It 'reads each object once over one connection, returns them in order and disposes it' {
        Use-Ldap

        $result = Get-Security -Name @('CN=b,DC=x', 'CN=a,DC=x', 'CN=b,DC=x') -Attribute @('gPLink')

        @($result.DistinguishedName) -join ';' | Should -BeExactly 'CN=b,DC=x;CN=a,DC=x;CN=b,DC=x'
        $result[0].Attribute | Should -BeExactly 'gPLink'
        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 2 -Exactly `
            -ParameterFilter {
            $Connection -is [TrackedLdapConnection] -and ($Attribute -join ',') -eq 'gPLink'
        }
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        $script:connection.Disposed | Should -Be $true
    }

    It 'serves a second call from the session cache without a connection' {
        Use-Ldap
        $null = Get-Security -Name @('CN=a,DC=x')

        $result = Get-Security -Name @('CN=a,DC=x')

        $result[0].DistinguishedName | Should -BeExactly 'CN=a,DC=x'
        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly
    }

    It 'reads only the objects not cached yet' {
        Use-Ldap
        $null = Get-Security -Name @('CN=a,DC=x')

        $result = Get-Security -Name @('CN=a,DC=x', 'CN=c,DC=x')

        @($result.DistinguishedName) -join ';' | Should -BeExactly 'CN=a,DC=x;CN=c,DC=x'
        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $SearchBase -eq 'CN=c,DC=x' }
        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 2 -Exactly
    }

    It 'reads a name given twice in different case only once' {
        Use-Ldap

        $null = Get-Security -Name @('CN=a,DC=x', 'cn=A,dc=x')

        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 1 -Exactly
    }

    It 'keeps separate cache entries per server and per extra attribute list' {
        Use-Ldap
        $null = Get-Security -Name @('CN=a,DC=x')

        $null = Get-Security -Name @('CN=a,DC=x') -Attribute @('gPLink')
        $null = Get-Security -Name @('CN=a,DC=x') -Server 'dc2'

        Should -Invoke Get-MtLdapObjectSecurity -ModuleName Maester -Times 3 -Exactly
    }

    It 'opens no connection for an empty list' {
        Use-Ldap

        @(Get-Security -Name @()).Count | Should -Be 0
        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 0 -Exactly
    }

    It 'throws and disposes the connection when a search fails' {
        Use-Ldap

        { Get-Security -Name @('CN=fail,DC=x') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when a search returns no object, and caches nothing for it' {
        Use-Ldap

        { Get-Security -Name @('CN=missing,DC=x') } | Should -Throw '*CN=missing,DC=x*no object*'
        { Get-Security -Name @('CN=missing,DC=x') } | Should -Throw '*no object*'
    }
}
