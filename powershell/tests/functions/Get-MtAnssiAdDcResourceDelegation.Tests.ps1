BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:lookup = @{}
    $script:lookup['CN=APP1,OU=Servers,DC=contoso,DC=com'] = @{
        Sid = 'S-1-5-21-1-2-3-1105'; Name = 'APP1'
    }

    function Get-ControllerFixture {
        param([string] $Name = 'DC1', [AllowNull()] [object] $Allowed, [string] $Type = 'Writable')
        [PSCustomObject]@{
            Type     = $Type
            Computer = [PSCustomObject]@{
                Name                                = $Name
                DistinguishedName                   = "CN=$Name,OU=Domain Controllers,DC=x"
                AllowedToActOnBehalfOfOtherIdentity = $Allowed
            }
        }
    }

    function Get-Delegation {
        param([AllowNull()] [object[]] $Controller)
        InModuleScope Maester -Parameters @{ Controller = $Controller; Lookup = $script:lookup } {
            param($Controller, $Lookup)
            Get-MtAnssiAdDcResourceDelegation -Controller $Controller -Lookup $Lookup
        }
    }
}

Describe 'Get-MtAnssiAdDcResourceDelegation' {
    It 'ignores a controller without the attribute' {
        @(Get-Delegation -Controller @(Get-ControllerFixture -Allowed $null)).Count | Should -Be 0
    }

    It 'names an allowed account found in the collected data' {
        $controller = Get-ControllerFixture -Allowed ([string[]]@('S-1-5-21-1-2-3-1105'))

        $result = @(Get-Delegation -Controller @($controller))

        $result.Count | Should -Be 1
        @($result[0].Allowed) | Should -Be @('APP1 (S-1-5-21-1-2-3-1105)')
    }

    It 'shows the SID of an account outside the collected data' {
        $controller = Get-ControllerFixture -Allowed ([string[]]@('S-1-5-21-9-9-9-1500'))

        @((Get-Delegation -Controller @($controller))[0].Allowed) |
            Should -Be @('S-1-5-21-9-9-9-1500')
    }

    It 'lists every allowed account in order' {
        $allowed = [string[]]@('S-1-5-21-9-9-9-1500', 'S-1-5-21-1-2-3-1105')
        $controller = Get-ControllerFixture -Allowed $allowed

        @((Get-Delegation -Controller @($controller))[0].Allowed) -join ',' |
            Should -BeExactly 'S-1-5-21-9-9-9-1500,APP1 (S-1-5-21-1-2-3-1105)'
    }

    It 'reports a controller whose descriptor allows nothing or could not be read' {
        $controller = Get-ControllerFixture -Allowed ([string[]]@())

        $result = @(Get-Delegation -Controller @($controller))

        $result.Count | Should -Be 1
        @($result[0].Allowed).Count | Should -Be 0
    }

    It 'returns the name, DN and type of the controller' {
        $controller = Get-ControllerFixture -Name 'RO1' -Type 'ReadOnly' `
            -Allowed ([string[]]@('S-1-5-21-1-2-3-1105'))

        $result = @(Get-Delegation -Controller @($controller))

        $result[0].Name | Should -Be 'RO1'
        $result[0].DistinguishedName | Should -Be 'CN=RO1,OU=Domain Controllers,DC=x'
        $result[0].Type | Should -Be 'ReadOnly'
    }

    It 'returns only the controllers with the attribute' {
        $result = @(Get-Delegation -Controller @(
                (Get-ControllerFixture -Name 'DC1' -Allowed $null)
                (Get-ControllerFixture -Name 'DC2' -Allowed ([string[]]@('S-1-5-21-1-2-3-1105')))
            ))

        ($result | ForEach-Object { $_.Name }) -join ',' | Should -Be 'DC2'
    }

    It 'returns nothing for no controller' {
        @(Get-Delegation -Controller $null).Count | Should -Be 0
    }
}
