BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:prefix = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,'

    function Get-ControllerFixture {
        param([string] $Name = 'DC1', [string] $Type = 'Writable')
        [PSCustomObject]@{
            Type     = $Type
            Computer = [PSCustomObject]@{
                Name              = $Name
                DistinguishedName = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            }
        }
    }

    function Get-SubscriptionFixture {
        param([string] $Dn)
        [PSCustomObject]@{ DistinguishedName = $Dn }
    }

    function Find-Missing {
        param([object[]] $Controller, [object[]] $Subscription)
        InModuleScope Maester -Parameters @{ C = $Controller; S = $Subscription } {
            , @(Get-MtAnssiAdControllerWithoutSysvolDfsr -Controller $C -Subscription $S)
        }
    }
}

Describe 'Get-MtAnssiAdControllerWithoutSysvolDfsr' {
    It 'returns nothing when every controller has a SYSVOL subscription' {
        $dn1 = $script:prefix + 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'
        $dn2 = $script:prefix + 'CN=DC2,OU=Domain Controllers,DC=contoso,DC=com'

        $result = Find-Missing -Controller @(
            Get-ControllerFixture -Name 'DC1'
            Get-ControllerFixture -Name 'DC2'
        ) -Subscription @(Get-SubscriptionFixture -Dn $dn1; Get-SubscriptionFixture -Dn $dn2)

        $result.Count | Should -Be 0
    }

    It 'returns the controllers without a subscription' {
        $dn1 = $script:prefix + 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'

        $result = Find-Missing -Controller @(
            Get-ControllerFixture -Name 'DC1'
            Get-ControllerFixture -Name 'DC2' -Type ReadOnly
        ) -Subscription @(Get-SubscriptionFixture -Dn $dn1)

        $result.Count | Should -Be 1
        $result[0].Computer.Name | Should -Be 'DC2'
        $result[0].Type | Should -Be 'ReadOnly'
    }

    It 'returns every controller when there is no subscription at all' {
        $result = Find-Missing -Controller @(
            Get-ControllerFixture -Name 'DC1'
            Get-ControllerFixture -Name 'DC2'
        ) -Subscription @()

        $result.Count | Should -Be 2
    }

    It 'returns every controller when the subscriptions are null' {
        $result = Find-Missing -Controller @(Get-ControllerFixture) -Subscription $null

        $result.Count | Should -Be 1
    }

    It 'compares the distinguished names without regard to case' {
        $dn = 'cn=sysvol subscription,cn=domain system volume,cn=dfsr-localsettings,' +
            'cn=dc1,ou=domain controllers,dc=contoso,dc=com'

        $result = Find-Missing -Controller @(Get-ControllerFixture) `
            -Subscription @(Get-SubscriptionFixture -Dn $dn)

        $result.Count | Should -Be 0
    }

    It 'does not accept a subscription of another controller' {
        $dn = $script:prefix + 'CN=DC9,OU=Domain Controllers,DC=contoso,DC=com'

        $result = Find-Missing -Controller @(Get-ControllerFixture) `
            -Subscription @(Get-SubscriptionFixture -Dn $dn)

        $result.Count | Should -Be 1
    }

    It 'does not accept another subscription of the same controller' {
        $dn = 'CN=Other Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,' +
            'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'

        $result = Find-Missing -Controller @(Get-ControllerFixture) `
            -Subscription @(Get-SubscriptionFixture -Dn $dn)

        $result.Count | Should -Be 1
    }

    It 'does not accept a replicated folder that is not the domain system volume' {
        $dn = 'CN=SYSVOL Subscription,CN=Other Folder,CN=DFSR-LocalSettings,' +
            'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'

        $result = Find-Missing -Controller @(Get-ControllerFixture) `
            -Subscription @(Get-SubscriptionFixture -Dn $dn)

        $result.Count | Should -Be 1
    }

    It 'returns an empty array without controllers' {
        $result = Find-Missing -Controller @() -Subscription @()

        $result.Count | Should -Be 0
    }
}
