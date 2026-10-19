BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-014.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDnsZoneInsecureUpdate' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDnsZoneInsecureUpdate {
        InModuleScope Maester { Test-MtAnssiAdDnsZoneInsecureUpdate }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Use-Ad {
        param(
            [object[]] $Finding = @(),
            [int] $ZoneCount = 3,
            [AllowNull()] [string] $DomainDn = 'DC=child,DC=contoso,DC=com'
        )
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DistinguishedName = $DomainDn; DnsRoot = 'child.contoso.com'; Forest = 'contoso.com'
            }
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=child,DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'DC=DomainDnsZones,DC=child,DC=contoso,DC=com'
            'DC=ForestDnsZones,DC=contoso,DC=com'
        }
        $zones = @(1..$ZoneCount | ForEach-Object { [PSCustomObject]@{ Name = "z$_" } })
        Mock Get-MtAnssiAdDnsZone -ModuleName Maester -MockWith ({ $zones }.GetNewClosure())
        $findingList = $Finding
        Mock Get-MtAnssiAdDnsZoneFinding -ModuleName Maester `
            -MockWith ({ $findingList }.GetNewClosure())
    }

    function Get-FindingFixture {
        param([string] $Name, [int] $Level)
        [PSCustomObject]@{
            Name = $Name
            DistinguishedName = "DC=$Name,CN=MicrosoftDNS"
            Level = $Level
        }
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdDnsZoneInsecureUpdate' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    It 'passes when no zone accepts nonsecure updates and reports the most severe level' {
        Use-Ad

        Test-MtAnssiAdDnsZoneInsecureUpdate | Should -Be $true

        Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
        Should -Invoke @detail -ParameterFilter {
            $Result -match '^None of the 3 DNS zones stored in Active Directory accepts nonsecure'
        }
    }

    It 'fails with severity <Expected> for zones of level <Levels>' -ForEach @(
        @{ Levels = '1'; Expected = 'Critical' }
        @{ Levels = '3'; Expected = 'Medium' }
        @{ Levels = '3,1'; Expected = 'Critical' }
    ) {
        $finding = @($Levels -split ',' | ForEach-Object { Get-FindingFixture -Name "zone$_" `
            -Level ([int]$_) })
        Use-Ad -Finding $finding

        Test-MtAnssiAdDnsZoneInsecureUpdate | Should -Be $false

        Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
        $count = $finding.Count
        $filter = [scriptblock]::Create(
            "`$Result -match '^$count of 3 DNS zones accept nonsecure dynamic updates'")
        Should -Invoke @detail -ParameterFilter $filter
    }

    It 'lists the zones with their severity' {
        Use-Ad -Finding @(Get-FindingFixture -Name 'apps_corp' -Level 3)

        $null = Test-MtAnssiAdDnsZoneInsecureUpdate

        Should -Invoke @detail -ParameterFilter {
            ($Result -replace '\\', '') -match ('\| apps_corp \| DC=apps_corp,CN=MicrosoftDNS' +
                ' \| Medium \|')
        }
    }

    It 'reads the zones of the domain naming context and the DNS partitions' {
        Use-Ad

        $null = Test-MtAnssiAdDnsZoneInsecureUpdate

        Should -Invoke Get-MtAnssiAdDnsZone -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            ($SearchBase -join ';') -eq ('CN=System,DC=child,DC=contoso,DC=com;' +
                'DC=DomainDnsZones,DC=child,DC=contoso,DC=com;' +
                'DC=ForestDnsZones,DC=contoso,DC=com') -and
            $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
        Should -Invoke Get-MtAnssiAdDnsZoneFinding -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            @($Zone).Count -eq 3 -and $DnsRoot -eq 'child.contoso.com' -and
                $Forest -eq 'contoso.com'
        }
        Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            @($Categories).Count -eq 1 -and $Categories -contains 'Domain'
        }
        Should -Invoke Get-MtAnssiAdNamingContextHead -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
    }

    It 'skips when no DNS zone is visible' {
        Use-Ad
        Mock Get-MtAnssiAdDnsZone -ModuleName Maester -MockWith { @() }

        $null -eq (Test-MtAnssiAdDnsZoneInsecureUpdate) | Should -Be $true

        Should -Invoke @detail -ParameterFilter {
            $SkippedBecause -eq 'Custom' -and
            $SkippedCustomReason -match '^No DNS zone stored in Active Directory is visible'
        }
    }

    It 'lets the exception reach the engine when the state cannot be read' {
        Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

        { Test-MtAnssiAdDnsZoneInsecureUpdate } | Should -Throw

    }

    It 'skips when the <Name> is missing' -ForEach @(
        @{ Name = 'domain name'; Property = 'DistinguishedName' }
        @{ Name = 'DNS name'; Property = 'DnsRoot' }
        @{ Name = 'forest name'; Property = 'Forest' }
    ) {
        Use-Ad
        $state = [PSCustomObject]@{
            Domain = [PSCustomObject]@{
                DistinguishedName = 'DC=x'; DnsRoot = 'x.com'; Forest = 'x.com'
            }
        }
        $state.Domain.$Property = ''
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

        $null -eq (Test-MtAnssiAdDnsZoneInsecureUpdate) | Should -Be $true

        Should -Invoke @detail -ParameterFilter {
            $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain or forest name'
        }
        Should -Invoke Get-MtAnssiAdDnsZone -ModuleName Maester -Times 0 -Exactly
    }

    It 'lets the exception reach the engine when <Command> fails' -ForEach @(
        @{ Command = 'Get-MtAnssiAdNamingContextHead' }
        @{ Command = 'Get-MtAnssiAdDnsZone' }
    ) {
        Use-Ad
        Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

        { Test-MtAnssiAdDnsZoneInsecureUpdate } | Should -Throw '*LDAP failed*'

    }
}
