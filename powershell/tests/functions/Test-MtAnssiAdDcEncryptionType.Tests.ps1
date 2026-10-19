BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-040.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDcEncryptionType' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDcEncryptionType {
        InModuleScope Maester { Test-MtAnssiAdDcEncryptionType }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-ComputerFixture {
        param(
            [string] $Name = 'DC1',
            [AllowNull()] [object] $Types = 24,
            [int] $PrimaryGroupId = 516,
            [int] $Uac = 532480,
            [switch] $NoProperty
        )
        $computer = [ordered]@{
            DistinguishedName  = "CN=$Name,OU=Domain Controllers,DC=contoso,DC=com"
            Name               = $Name
            PrimaryGroupId     = $PrimaryGroupId
            UserAccountControl = $Uac
        }
        if (-not $NoProperty) { $computer['SupportedEncryptionTypes'] = $Types }
        [PSCustomObject]$computer
    }

    function Use-Ad {
        param([AllowNull()] [object[]] $Computer = @(), [object[]] $DomainController = @())
        $state = [PSCustomObject]@{ Computers = $Computer; DomainControllers = $DomainController }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDcEncryptionType' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict and severity' {
        It 'passes for AES only and reports the most severe severity' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1' -Types 24)
                (Get-ComputerFixture -Name 'DC2' -Types 56)
            )

            Test-MtAnssiAdDcEncryptionType | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Severity -eq 'High' -and
                $Result -match '^All 2 domain controllers only support AES'
            }
        }

        It '<Name> fails with severity <Expected>' -ForEach @(
            @{ Name = 'RC4 with AES'; Types = 28; Expected = 'Low' }
            @{ Name = 'RC4 only'; Types = 4; Expected = 'Medium' }
            @{ Name = 'no value'; Types = $null; Expected = 'Medium' }
            @{ Name = 'a value of 0'; Types = 0; Expected = 'Medium' }
            @{ Name = 'DES-CBC-CRC'; Types = 25; Expected = 'High' }
            @{ Name = 'DES-CBC-MD5'; Types = 26; Expected = 'High' }
            @{ Name = 'DES, RC4 and no AES'; Types = 7; Expected = 'High' }
        ) {
            Use-Ad -Computer @(Get-ComputerFixture -Types $Types)

            Test-MtAnssiAdDcEncryptionType | Should -Be $false

            $filter = [scriptblock]::Create("`$Severity -eq '$Expected'")
            Should -Invoke @detail -ParameterFilter $filter
        }

        It 'reports the worst severity of several controllers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1' -Types 28)
                (Get-ComputerFixture -Name 'DC2' -Types 4)
                (Get-ComputerFixture -Name 'DC3' -Types 24)
            )

            Test-MtAnssiAdDcEncryptionType | Should -Be $false

            Should -Invoke @detail -ParameterFilter { $Severity -eq 'Medium' }
        }

        It 'reports High when one controller uses DES among weaker findings' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1' -Types 28)
                (Get-ComputerFixture -Name 'DC2' -Types 27)
            )

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke @detail -ParameterFilter { $Severity -eq 'High' }
        }

        It 'fails for a controller set to use DES keys only' {
            Use-Ad -Computer @(Get-ComputerFixture -Types 24 -Uac (532480 -bor 0x200000))

            Test-MtAnssiAdDcEncryptionType | Should -Be $false

            Should -Invoke @detail -ParameterFilter { $Severity -eq 'High' }
        }

        It 'checks read-only domain controllers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1' -Types 24)
                (Get-ComputerFixture -Name 'RO1' -Types 28 -PrimaryGroupId 521 -Uac 83890176)
            )

            Test-MtAnssiAdDcEncryptionType | Should -Be $false
        }

        It 'finds a controller through its directory entry when its primary group is unusual' {
            $computer = Get-ComputerFixture -Name 'DC9' -Types 28 -PrimaryGroupId 515 -Uac 4096
            $entry = [PSCustomObject]@{ ServerReference = $computer.DistinguishedName }
            Use-Ad -Computer @($computer) -DomainController @($entry)

            Test-MtAnssiAdDcEncryptionType | Should -Be $false
        }

        It 'ignores computers that are not domain controllers' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC1' -Types 24)
                (Get-ComputerFixture -Name 'SRV1' -Types 4 -PrimaryGroupId 515 -Uac 4096)
            )

            Test-MtAnssiAdDcEncryptionType | Should -Be $true
        }
    }

    Context 'result text' {
        It 'lists the controllers worst first, then by name, with their findings' {
            Use-Ad -Computer @(
                (Get-ComputerFixture -Name 'DC-C' -Types 28)
                (Get-ComputerFixture -Name 'DC-B' -Types 4)
                (Get-ComputerFixture -Name 'DC-Z' -Types 27)
                (Get-ComputerFixture -Name 'DC-A' -Types 27)
                (Get-ComputerFixture -Name 'DC-OK' -Types 24)
            )

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^4 of 5 domain controllers support a weak Kerberos' -and
                $text -match ('(?s)DC-A \| Writable \| .* \| DES enabled \| High \|.*' +
                    'DC-Z \| .*High \|.*' +
                    'DC-B \| Writable \| RC4 \(0x4\) \| ' +
                    'No AES128 or AES256, RC4 enabled \| Medium \|.*' +
                    'DC-C \| Writable \| RC4, AES128, AES256 \(0x1C\) \| ' +
                    'RC4 enabled \| Low \|') -and
                $text -notmatch 'DC-OK'
            }
        }

        It 'shows Not set for a controller without a value' {
            Use-Ad -Computer @(Get-ComputerFixture -Types $null)

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'Not set \| No AES128 or AES256 \| Medium'
            }
        }

        It 'shows the type of a read-only domain controller' {
            Use-Ad -Computer @(
                Get-ComputerFixture -Name 'RO1' -Types 28 -PrimaryGroupId 521 -Uac 83890176)

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke @detail -ParameterFilter { $Result -match 'RO1 \| ReadOnly \|' }
        }

        It 'escapes markdown in the controller name' {
            $evil = '[click](https://evil.example)|x'
            Use-Ad -Computer @(Get-ComputerFixture -Name $evil -Types 28)

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data requested' {
        It 'reads the Computers and DomainControllers categories' {
            Use-Ad -Computer @(Get-ComputerFixture)

            $null = Test-MtAnssiAdDcEncryptionType

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 2 -and $Categories -contains 'Computers' -and
                $Categories -contains 'DomainControllers'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no domain controller computer account is found' {
            Use-Ad -Computer @(Get-ComputerFixture -PrimaryGroupId 515 -Uac 4096)

            Test-MtAnssiAdDcEncryptionType | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain controller'
            }
        }

        It 'is skipped when the computers do not carry the attribute' {
            Use-Ad -Computer @(Get-ComputerFixture -NoProperty)

            Test-MtAnssiAdDcEncryptionType | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and
                $SkippedCustomReason -match 'msDS-SupportedEncryptionTypes'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDcEncryptionType } | Should -Throw 'LDAP bind failed'

        }
    }
}
