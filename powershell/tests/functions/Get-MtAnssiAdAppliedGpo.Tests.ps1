BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainDn = 'DC=x'

    function Get-Gpo {
        param([string] $Id)
        "cn={$Id},cn=policies,cn=system,DC=x"
    }

    function Get-Link {
        param([string] $Id, [int] $Options = 0)
        "[LDAP://$(Get-Gpo -Id $Id);$Options]"
    }

    function Get-ContainerFixture {
        param([string] $Dn, [string] $GpLink = '', [AllowNull()] [object] $GpOptions = $null)
        [PSCustomObject]@{
            DistinguishedName = $Dn
            Attribute         = [ordered]@{ gPLink = $GpLink; gPOptions = $GpOptions }
        }
    }

    function Get-Applied {
        param([string[]] $Name, [object[]] $Container)
        $parameters = @{ Name = $Name; Container = $Container; DomainDn = $script:domainDn }
        InModuleScope Maester -Parameters $parameters {
            param($Name, $Container, $DomainDn)
            @(Get-MtAnssiAdAppliedGpo -DistinguishedName $Name -Container $Container `
                    -DomainDn $DomainDn)
        }
    }

    function Format-Result {
        param([object[]] $Row)
        @($Row | ForEach-Object { "$(($_.DistinguishedName -split ',')[0]):$($_.Count)" }) -join ';'
    }
}

Describe 'Get-MtAnssiAdAppliedGpo' {
    It 'applies enabled links of every container up to the domain root' {
        $containers = @(
            Get-ContainerFixture -Dn 'DC=x' -GpLink (Get-Link -Id 'D')
            Get-ContainerFixture -Dn 'OU=t0,DC=x' `
                -GpLink ((Get-Link -Id 'A') + (Get-Link -Id 'B' -Options 1))
            Get-ContainerFixture -Dn 'OU=adm,OU=t0,DC=x' -GpLink (Get-Link -Id 'C')
        )

        $names = @('CN=alice,OU=adm,OU=t0,DC=x', 'CN=bob,OU=t0,DC=x')
        $result = Get-Applied -Name $names -Container $containers

        Format-Result -Row $result | Should -BeExactly 'cn={A}:2;cn={D}:2;cn={C}:1'
        $result[0].DistinguishedName | Should -BeExactly (Get-Gpo -Id 'A')
    }

    It 'stops non-enforced links above a container that blocks inheritance' {
        $containers = @(
            Get-ContainerFixture -Dn 'DC=x' `
                -GpLink ((Get-Link -Id 'D') + (Get-Link -Id 'E' -Options 2))
            Get-ContainerFixture -Dn 'OU=t0,DC=x' -GpLink (Get-Link -Id 'A') -GpOptions 1
            Get-ContainerFixture -Dn 'OU=adm,OU=t0,DC=x' -GpLink (Get-Link -Id 'C')
        )

        $result = Get-Applied -Name @('CN=alice,OU=adm,OU=t0,DC=x') -Container $containers

        Format-Result -Row $result | Should -BeExactly 'cn={A}:1;cn={C}:1;cn={E}:1'
    }

    It 'never applies a disabled link, even enforced' {
        $containers = @(
            Get-ContainerFixture -Dn 'DC=x' -GpLink (Get-Link -Id 'D' -Options 3)
            Get-ContainerFixture -Dn 'OU=t0,DC=x' -GpOptions 0
        )

        @(Get-Applied -Name @('CN=alice,OU=t0,DC=x') -Container $containers).Count | Should -Be 0
    }

    It 'counts a GPO linked twice on a chain once per object' {
        $containers = @(
            Get-ContainerFixture -Dn 'DC=x' -GpLink (Get-Link -Id 'A')
            Get-ContainerFixture -Dn 'OU=t0,DC=x' `
                -GpLink ('[ldap://CN={A},CN=Policies,CN=System,DC=x;0]')
        )

        Format-Result -Row (Get-Applied -Name @('CN=alice,OU=t0,DC=x') -Container $containers) |
            Should -Be 'cn={A}:1'
    }

    It 'reads the link of an object right below the domain root' {
        $containers = @(Get-ContainerFixture -Dn 'DC=x' -GpLink (Get-Link -Id 'D'))

        Format-Result -Row (Get-Applied -Name @('CN=alice,DC=x') -Container $containers) |
            Should -BeExactly 'cn={D}:1'
    }

    It 'reads a link written in lower case' {
        $containers = @(Get-ContainerFixture -Dn 'DC=x' `
            -GpLink '[ldap://cn={L},cn=policies,cn=system,DC=x;0]')

        Format-Result -Row (Get-Applied -Name @('CN=alice,DC=x') -Container $containers) |
            Should -BeExactly 'cn={L}:1'
    }

    It 'ignores text in gPLink that is not a link' {
        $containers = @(Get-ContainerFixture -Dn 'DC=x' -GpLink ' [junk] ')

        @(Get-Applied -Name @('CN=alice,DC=x') -Container $containers).Count | Should -Be 0
    }

    It 'throws when a container of the chain was not read' {
        $containers = @(Get-ContainerFixture -Dn 'DC=x')

        { Get-Applied -Name @('CN=alice,OU=t0,DC=x') -Container $containers } |
            Should -Throw "*'OU=t0,DC=x' was not read*"
    }

    It 'counts every account of a container and works the chain out once per container' {
        $containers = @(
            Get-ContainerFixture -Dn 'DC=x'
            Get-ContainerFixture -Dn 'OU=t0,DC=x' -GpLink (Get-Link -Id 'A')
        )
        Mock Get-MtAnssiAdParentContainer -ModuleName Maester -MockWith { 'OU=t0,DC=x' }

        $result = Get-Applied -Name @('CN=a,OU=t0,DC=x', 'CN=b,OU=t0,DC=x', 'CN=c\,d,OU=t0,DC=x') `
            -Container $containers

        Format-Result -Row $result | Should -BeExactly 'cn={A}:3'
        Should -Invoke Get-MtAnssiAdParentContainer -ModuleName Maester -Times 1 -Exactly
    }

    It 'returns nothing for no object' {
        @(Get-Applied -Name @() -Container @()).Count | Should -Be 0
    }
}
