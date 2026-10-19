BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-004.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdPkiWeakCertificate' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdPkiWeakCertificate {
        InModuleScope Maester { Test-MtAnssiAdPkiWeakCertificate }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Use-Ad {
        param([object[]] $Finding = @(), [int[]] $CertificateCount = @(2, 1))
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DistinguishedName = 'DC=child,DC=contoso,DC=com' }
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        Mock Get-MtAnssiAdNamingContextHead -ModuleName Maester -MockWith {
            'DC=child,DC=contoso,DC=com'
            'CN=Configuration,DC=contoso,DC=com'
            'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        }
        $objects = @(foreach ($count in $CertificateCount) {
                $values = @(foreach ($n in 1..$count) { , [byte[]]($n) })
                [PSCustomObject]@{ DistinguishedName = "CN=o$count"; Certificate = $values }
            })
        Mock Get-MtAnssiAdCaCertificate -ModuleName Maester -MockWith ({ $objects }.GetNewClosure())
        $findingList = $Finding
        Mock Get-MtAnssiAdCertificateFinding -ModuleName Maester `
            -MockWith ({ $findingList }.GetNewClosure())
    }

    function Get-FindingFixture {
        param([string] $Subject, [int] $Level, [AllowNull()] [Nullable[datetime]] $NotAfter)
        [PSCustomObject]@{
            DistinguishedName = 'CN=NTAuthCertificates,CN=Public Key Services'
            Subject           = $Subject
            NotAfter          = $NotAfter
            Problem           = [string[]]@('DSA key', 'Signature sha1DSA, not SHA-2 or SHA-3')
            Level             = $Level
        }
    }

    function Get-Severity {
        param([string] $Expected)
        [scriptblock]::Create("`$Severity -eq '$Expected'")
    }
}

Describe 'Test-MtAnssiAdPkiWeakCertificate' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    It 'passes when no certificate is weak and reports the most severe level' {
        Use-Ad

        Test-MtAnssiAdPkiWeakCertificate | Should -Be $true

        Should -Invoke @detail -ParameterFilter (Get-Severity -Expected 'Critical')
        Should -Invoke @detail -ParameterFilter {
            $Result -match '^None of the 3 certificates stored in Active Directory has a weak key'
        }
    }

    It 'passes when no certificate is stored' {
        Use-Ad -CertificateCount @()

        Test-MtAnssiAdPkiWeakCertificate | Should -Be $true

        Should -Invoke @detail -ParameterFilter { $Result -match '^None of the 0 certificates' }
    }

    It 'fails with severity <Expected> for certificates of level <Levels>' -ForEach @(
        @{ Levels = '1'; Expected = 'Critical' }
        @{ Levels = '2'; Expected = 'High' }
        @{ Levels = '3'; Expected = 'Medium' }
        @{ Levels = '3,2'; Expected = 'High' }
        @{ Levels = '3,1,2'; Expected = 'Critical' }
    ) {
        $finding = @($Levels -split ',' | ForEach-Object {
                Get-FindingFixture -Subject "CN=ca$_" -Level ([int]$_) -NotAfter $null })
        Use-Ad -Finding $finding

        Test-MtAnssiAdPkiWeakCertificate | Should -Be $false

        Should -Invoke @detail -ParameterFilter (Get-Severity -Expected $Expected)
        $count = $finding.Count
        $filter = [scriptblock]::Create(
            "`$Result -match ('^$count of the 3 certificates stored in Active Directory have a' +
                ' weak')")
        Should -Invoke @detail -ParameterFilter $filter
    }

    It 'lists the certificates with their expiry, problems and severity' {
        $date = [datetime]::new(2019, 3, 5, 0, 0, 0, [System.DateTimeKind]::Utc)
        Use-Ad -Finding @(Get-FindingFixture -Subject 'CN=Old_CA' -Level 1 -NotAfter $date)

        $null = Test-MtAnssiAdPkiWeakCertificate

        Should -Invoke @detail -ParameterFilter {
            ($Result -replace '\\', '') -match (('\| CN=NTAuthCertificates,CN=Public Key' +
                ' Services \| ') +
                ('CN=Old_CA \| 2019-03-05 \| DSA key; Signature sha1DSA, not SHA-2 or SHA-3 \|' +
                    ' Critical \|'))
        }
    }

    It 'shows Unknown for a certificate without an expiry date' {
        Use-Ad -Finding @(Get-FindingFixture -Subject '' -Level 2 -NotAfter $null)

        $null = Test-MtAnssiAdPkiWeakCertificate

        Should -Invoke @detail -ParameterFilter { $Result -match '\|  \| Unknown \| .* \| High \|' }
    }

    It 'reads the certificates below the Services container of the Configuration partition' {
        Use-Ad

        $null = Test-MtAnssiAdPkiWeakCertificate

        Should -Invoke Get-MtAnssiAdCaCertificate -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $SearchBase -eq 'CN=Services,CN=Configuration,DC=contoso,DC=com' -and
            $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
        Should -Invoke Get-MtAnssiAdCertificateFinding -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { @($Object).Count -eq 2 }
        Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            @($Categories).Count -eq 1 -and $Categories -contains 'Domain'
        }
        Should -Invoke Get-MtAnssiAdNamingContextHead -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
    }

    It 'lets the exception reach the engine when the state cannot be read' {
        Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

        { Test-MtAnssiAdPkiWeakCertificate } | Should -Throw

    }

    It 'lets the exception reach the engine when <Command> fails' -ForEach @(
        @{ Command = 'Get-MtAnssiAdNamingContextHead' }
        @{ Command = 'Get-MtAnssiAdCaCertificate' }
    ) {
        Use-Ad
        Mock $Command -ModuleName Maester -MockWith { throw 'LDAP failed' }

        { Test-MtAnssiAdPkiWeakCertificate } | Should -Throw '*LDAP failed*'

        Should -Invoke Get-MtAnssiAdCertificateFinding -ModuleName Maester -Times 0 -Exactly
    }
}
