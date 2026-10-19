BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    function Get-DomainFixture {
        param(
            [AllowNull()] [string] $DnsRoot = 'child.root.local',
            [AllowNull()] [string] $Forest = 'root.local',
            [AllowNull()] [string] $Sid = 'S-1-5-21-1-1-1'
        )
        $sidValue = $null
        if ($Sid) { $sidValue = [PSCustomObject]@{ Value = $Sid } }
        [PSCustomObject]@{ DnsRoot = $DnsRoot; Forest = $Forest; DomainSID = $sidValue }
    }

    function Get-TrustFixture {
        param(
            [string] $Partner = 'root.local', $Attributes = 0x20,
            [AllowNull()] [string] $Sid = 'S-1-5-21-9-9-9'
        )
        $sidValue = $null
        if ($Sid) { $sidValue = [PSCustomObject]@{ Value = $Sid } }
        [PSCustomObject]@{ TrustPartner = $Partner; TrustAttributes = $Attributes; Sid = $sidValue }
    }

    function Get-RootSid {
        param([object] $Domain, [AllowNull()] [object[]] $Trust)
        InModuleScope Maester -Parameters @{ Domain = $Domain; Trust = $Trust } {
            param($Domain, $Trust)
            Get-MtAnssiAdForestRootSid -Domain $Domain -Trust $Trust
        }
    }
}

Describe 'Get-MtAnssiAdForestRootSid' {
    Context 'in the forest root domain' {
        It 'returns the SID of the domain, whatever the trusts are' {
            $domain = Get-DomainFixture -DnsRoot 'root.local' -Sid 'S-1-5-21-5-5-5'

            Get-RootSid -Domain $domain -Trust @(Get-TrustFixture) |
                Should -BeExactly 'S-1-5-21-5-5-5'
        }

        It 'compares the names without regard to case' {
            $domain = Get-DomainFixture -DnsRoot 'ROOT.local' -Forest 'root.LOCAL' `
                -Sid 'S-1-5-21-5-5-5'

            Get-RootSid -Domain $domain -Trust $null | Should -BeExactly 'S-1-5-21-5-5-5'
        }

        It 'throws when the SID of the domain was not collected' {
            $domain = Get-DomainFixture -DnsRoot 'root.local' -Sid $null

            { Get-RootSid -Domain $domain -Trust @() } |
                Should -Throw -ExpectedMessage '*was not collected*'
        }
    }

    Context 'in a child domain' {
        It 'takes the SID from the trust to the parent inside the forest' {
            $trust = @(
                Get-TrustFixture -Partner 'other.local' -Attributes 0 -Sid 'S-1-5-21-2-2-2'
                Get-TrustFixture -Partner 'root.local' -Attributes 0x20 -Sid 'S-1-5-21-9-9-9'
            )

            Get-RootSid -Domain (Get-DomainFixture) -Trust $trust |
                Should -BeExactly 'S-1-5-21-9-9-9'
        }

        It 'matches the partner without regard to case' {
            $trust = @(Get-TrustFixture -Partner 'ROOT.Local')

            Get-RootSid -Domain (Get-DomainFixture) -Trust $trust |
                Should -BeExactly 'S-1-5-21-9-9-9'
        }

        It 'accepts the inside-forest flag among other flags and as text' -ForEach @(
            @{ Attributes = 0x20 }
            @{ Attributes = 0x2C }
            @{ Attributes = '32' }
        ) {
            $trust = @(Get-TrustFixture -Attributes $Attributes)

            Get-RootSid -Domain (Get-DomainFixture) -Trust $trust |
                Should -BeExactly 'S-1-5-21-9-9-9'
        }

        It 'ignores a trust that is not inside the forest or has no SID' -ForEach @(
            @{ Attributes = 0; Sid = 'S-1-5-21-9-9-9' }
            @{ Attributes = 0x8; Sid = 'S-1-5-21-9-9-9' }
            @{ Attributes = $null; Sid = 'S-1-5-21-9-9-9' }
            @{ Attributes = 0x20; Sid = $null }
        ) {
            $trust = @(Get-TrustFixture -Attributes $Attributes -Sid $Sid)

            { Get-RootSid -Domain (Get-DomainFixture) -Trust $trust } |
                Should -Throw -ExpectedMessage (
                    "*'root.local' was not found among the trusts of 'child.root.local'*")
        }

        It 'throws when the parent is not the forest root, as in a grandchild domain' {
            $trust = @(Get-TrustFixture -Partner 'child.root.local')

            $domain = Get-DomainFixture -DnsRoot 'grand.child.root.local'

            { Get-RootSid -Domain $domain -Trust $trust } |
                Should -Throw -ExpectedMessage '*was not found among the trusts*'
        }

        It 'throws when there are no trusts' -ForEach @(
            @{ Trust = @() }
            @{ Trust = $null }
        ) {
            { Get-RootSid -Domain (Get-DomainFixture) -Trust $Trust } |
                Should -Throw -ExpectedMessage '*was not found among the trusts*'
        }
    }

    It 'throws when the forest or the domain name is missing' -ForEach @(
        @{ DnsRoot = $null; Forest = 'root.local' }
        @{ DnsRoot = 'root.local'; Forest = $null }
    ) {
        $domain = Get-DomainFixture -DnsRoot $DnsRoot -Forest $Forest

        { Get-RootSid -Domain $domain -Trust @() } | Should -Throw -ExpectedMessage '*is unknown*'
    }
}
