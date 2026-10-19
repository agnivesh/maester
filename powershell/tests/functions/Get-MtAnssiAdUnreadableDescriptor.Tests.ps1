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

    function Get-Account {
        param([string] $Name)
        [PSCustomObject]@{ DistinguishedName = "CN=$Name,DC=contoso,DC=com"; Name = $Name }
    }

    function Use-Ldap {
        param([hashtable] $Descriptor, [string[]] $NoEntry = @(), [string] $FailOn = '')
        $script:descriptor = $Descriptor
        $script:noEntry = $NoEntry
        $script:failDn = $FailOn
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            if ($SearchBase -eq $script:failDn) { throw 'LDAP search failed' }
            if ($script:noEntry -notcontains $SearchBase) {
                [PSCustomObject]@{
                    DistinguishedName    = $SearchBase
                    nTSecurityDescriptor = $script:descriptor[$SearchBase]
                }
            }
        }
    }

    function Get-Unreadable {
        param([object[]] $Account)
        $evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        $parameters = @{ Account = $Account; Evidence = $evidence }
        InModuleScope Maester -Parameters $parameters {
            param($Account, $Evidence)
            @(Get-MtAnssiAdUnreadableDescriptor -Account $Account -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdUnreadableDescriptor' {
    It 'returns the accounts whose descriptor is missing and keeps the readable ones out' {
        $accounts = @(Get-Account -Name 'alice'; Get-Account -Name 'bob'; Get-Account -Name 'carol')
        Use-Ldap -Descriptor @{
            'CN=alice,DC=contoso,DC=com' = [byte[]](1, 0, 4, 128)
            'CN=carol,DC=contoso,DC=com' = [PSCustomObject]@{ Owner = 'x' }
        }

        $result = Get-Unreadable -Account $accounts

        @($result.Name) | Should -Be @('bob')
    }

    It 'returns an account whose search gives back no entry' {
        Use-Ldap -Descriptor @{} -NoEntry 'CN=alice,DC=contoso,DC=com'

        $result = Get-Unreadable -Account @(Get-Account -Name 'alice')

        @($result.Name) | Should -Be @('alice')
    }

    It 'reads owner, group and DACL of each account with a base search over one connection' {
        Use-Ldap -Descriptor @{ 'CN=alice,DC=contoso,DC=com' = [byte[]](1) }

        $null = Get-Unreadable -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=alice,DC=contoso,DC=com' -and $Scope -eq 'Base' -and
            @($Attributes) -join ',' -eq 'nTSecurityDescriptor' -and $PageSize -eq 0 -and
            $Connection -is [TrackedLdapConnection] -and
            [int]$SecurityDescriptorFlags -eq 7
        }
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 2 -Exactly
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when a search fails and disposes the connection' {
        Use-Ldap -Descriptor @{} -FailOn 'CN=bob,DC=contoso,DC=com'

        { Get-Unreadable -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'

        $script:connection.Disposed | Should -Be $true
    }

    It 'returns nothing for no account' {
        Use-Ldap -Descriptor @{}

        (Get-Unreadable -Account @()).Count | Should -Be 0
    }
}
