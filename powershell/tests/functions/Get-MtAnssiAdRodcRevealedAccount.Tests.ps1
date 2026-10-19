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

    function Get-Rodc {
        param([string] $Name)
        [PSCustomObject]@{
            Type     = 'ReadOnly'
            Computer = [PSCustomObject]@{ Name = $Name; DistinguishedName = "CN=$Name,OU=DC,DC=x" }
        }
    }

    function Get-Account {
        param([string] $Name)
        [PSCustomObject]@{ DistinguishedName = "CN=$Name,DC=x"; Name = $Name }
    }

    function Use-Ldap {
        param([hashtable] $Revealed, [string] $FailOn = '')
        $script:revealed = $Revealed
        $script:failDn = $FailOn
        $script:connection = [TrackedLdapConnection]::new()
        $tracked = $script:connection
        Mock New-MtAdProtocolConnection -ModuleName Maester -MockWith ({ $tracked }.GetNewClosure())
        Mock Get-MtLdapRangedValue -ModuleName Maester -MockWith {
            if ($DistinguishedName -eq $script:failDn) { throw 'LDAP search failed' }
            foreach ($value in $script:revealed[$DistinguishedName]) { $value }
        }
    }

    function Get-Revealed {
        param([object[]] $Controller, [object[]] $Account)
        $parameters = @{
            Controller = $Controller; Account = $Account
            Evidence   = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        InModuleScope Maester -Parameters $parameters {
            param($Controller, $Account, $Evidence)
            @(Get-MtAnssiAdRodcRevealedAccount -Controller $Controller -Account $Account `
                    -ProtocolEvidence $Evidence)
        }
    }
}

Describe 'Get-MtAnssiAdRodcRevealedAccount' {
    It 'returns each listed account cached on an RODC, read from DN-with-binary values' {
        Use-Ldap -Revealed @{
            'CN=RODC1,OU=DC,DC=x' = @(
                'B:96:0A00000000000000:CN=alice,DC=x'
                'B:96:1F00000000000000:CN=alice,DC=x'
                'B:96:0A00000000000000:CN=carol,DC=x'
            )
        }

        $result = Get-Revealed -Controller @(Get-Rodc -Name 'RODC1') `
            -Account @(Get-Account -Name 'alice'; Get-Account -Name 'bob')

        $result.Count | Should -Be 1
        $result[0].Account.Name | Should -BeExactly 'alice'
        $result[0].Controller.Computer.Name | Should -BeExactly 'RODC1'
    }

    It 'reads a value with an empty binary part' {
        Use-Ldap -Revealed @{ 'CN=RODC1,OU=DC,DC=x' = @('B:0::CN=alice,DC=x') }

        $result = Get-Revealed -Controller @(Get-Rodc -Name 'RODC1') `
            -Account @(Get-Account -Name 'alice')

        $result.Count | Should -Be 1
    }

    It 'also accepts a plain distinguished name and ignores case' {
        Use-Ldap -Revealed @{ 'CN=RODC1,OU=DC,DC=x' = @('cn=ALICE,dc=x') }

        $result = Get-Revealed -Controller @(Get-Rodc -Name 'RODC1') `
            -Account @(Get-Account -Name 'alice')

        $result.Count | Should -Be 1
    }

    It 'returns one pair per RODC that cached the account' {
        Use-Ldap -Revealed @{
            'CN=RODC1,OU=DC,DC=x' = @('B:8:00:CN=alice,DC=x')
            'CN=RODC2,OU=DC,DC=x' = @('B:8:00:CN=alice,DC=x')
            'CN=RODC3,OU=DC,DC=x' = @()
        }

        $result = Get-Revealed -Controller @(
            Get-Rodc -Name 'RODC1'; Get-Rodc -Name 'RODC2'; Get-Rodc -Name 'RODC3'
        ) -Account @(Get-Account -Name 'alice')

        @($result.Controller.Computer.Name) | Should -Be @('RODC1', 'RODC2')
    }

    It 'reads msDS-RevealedUsers of every RODC over one connection and disposes it' {
        Use-Ldap -Revealed @{}

        $null = Get-Revealed -Controller @(Get-Rodc -Name 'RODC1'; Get-Rodc -Name 'RODC2') `
            -Account @(Get-Account -Name 'alice')

        Should -Invoke New-MtAdProtocolConnection -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        Should -Invoke Get-MtLdapRangedValue -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $DistinguishedName -eq 'CN=RODC2,OU=DC,DC=x' -and
            $AttributeName -eq 'msDS-RevealedUsers' -and $Connection -is [TrackedLdapConnection]
        }
        $script:connection.Disposed | Should -Be $true
    }

    It 'throws when a read fails and disposes the connection' {
        Use-Ldap -Revealed @{} -FailOn 'CN=RODC1,OU=DC,DC=x'

        $rodc = @(Get-Rodc -Name 'RODC1')
        { Get-Revealed -Controller $rodc -Account @(Get-Account -Name 'alice') } |
            Should -Throw -ExpectedMessage 'LDAP search failed'

        $script:connection.Disposed | Should -Be $true
    }
}
