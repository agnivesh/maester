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
        [PSCustomObject]@{ DistinguishedName = "CN=$Name,DC=x"; Name = $Name }
    }

    function Use-Ldap {
        param([hashtable] $Assigned = @{}, [hashtable] $Silo = @{}, [string] $FailOn = '')
        $script:assigned = $Assigned
        $script:silo = $Silo
        $script:failDn = $FailOn
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Invoke-MtLdapSearch -ModuleName Maester -MockWith {
            if ($SearchBase -eq $script:failDn) { throw 'LDAP search failed' }
            [PSCustomObject]@{ 'msDS-AssignedAuthNPolicySilo' = $script:assigned[$SearchBase] }
        }
        Mock Read-MtAnssiAdAuthenticationSilo -ModuleName Maester -MockWith {
            $script:silo[$DistinguishedName]
        }
    }

    function Get-Silo {
        param([string] $Name, [bool] $Enforced = $true, [string[]] $Member = @())
        $set = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($dn in $Member) { $null = $set.Add($dn) }
        [PSCustomObject]@{ Name = $Name; Enforced = $Enforced; Member = $set }
    }

    function Get-Status {
        param([object[]] $Account)
        $evidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        InModuleScope Maester -Parameters @{ Account = $Account; Evidence = $evidence } {
            param($Account, $Evidence)
            @(Get-MtAnssiAdSiloAssignment -Account $Account -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdSiloAssignment' {
    It 'reports <Expected> for <Case>' -ForEach @(
        @{
            Case = 'an account without a silo'; Silo = ''; Enforced = $true; Member = $false
            Expected = 'not assigned to a silo'
        }
        @{
            Case = 'a silo that is not enforced'; Silo = 'S1'; Enforced = $false; Member = $true
            Expected = 'silo not enforced'
        }
        @{
            Case = 'a silo without access'; Silo = 'S1'; Enforced = $true; Member = $false
            Expected = 'not granted access to the silo'
        }
        @{
            Case = 'an account in an enforced silo'; Silo = 'S1'; Enforced = $true; Member = $true
            Expected = $null
        }
    ) {
        $assigned = @{}
        if ($Silo) { $assigned['CN=alice,DC=x'] = 'CN=S1,DC=x' }
        $members = @()
        if ($Member) { $members = @('cn=ALICE,dc=x') }
        $siloObject = Get-Silo -Name 'S1' -Enforced $Enforced -Member $members
        Use-Ldap -Assigned $assigned -Silo @{ 'CN=S1,DC=x' = $siloObject }

        $status = Get-Status -Account @(Get-Account -Name 'alice')

        $status.Count | Should -Be 1
        $status[0].Account.Name | Should -BeExactly 'alice'
        $status[0].Problem | Should -Be $Expected
        $status[0].Silo | Should -BeExactly $Silo
    }

    It 'reads each assigned silo once' {
        Use-Ldap -Assigned @{ 'CN=alice,DC=x' = 'CN=S1,DC=x'; 'CN=bob,DC=x' = 'CN=S1,DC=x' } `
            -Silo @{ 'CN=S1,DC=x' = (Get-Silo -Name 'S1') }

        $null = Get-Status -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        Should -Invoke Read-MtAnssiAdAuthenticationSilo -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $DistinguishedName -eq 'CN=S1,DC=x' -and $Connection -is [TrackedLdapConnection]
        }
    }

    It 'reads the assigned silo of each account with a base search over one connection' {
        Use-Ldap

        $null = Get-Status -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Invoke-MtLdapSearch -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            $SearchBase -eq 'CN=bob,DC=x' -and $Scope -eq 'Base' -and $PageSize -eq 0 -and
            @($Attributes) -join ',' -eq 'msDS-AssignedAuthNPolicySilo' -and
            $Connection -is [TrackedLdapConnection]
        }
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when a read fails and disposes the connection' {
        Use-Ldap -FailOn 'CN=alice,DC=x'

        { Get-Status -Account @(Get-Account -Name 'alice') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'
        $script:connection.Disposed | Should -Be $true
    }

    It 'returns nothing for no account' {
        Use-Ldap

        (Get-Status -Account @()).Count | Should -Be 0
    }
}
