BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-075.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDomainSmartCardPasswordExpiration' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDomainSmartCardPasswordExpiration {
        InModuleScope Maester { Test-MtAnssiAdDomainSmartCardPasswordExpiration }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Use-Domain {
        param(
            [AllowNull()] [object] $Mode = 'Windows2016Domain',
            [AllowNull()] [object] $Expire = $true,
            [switch] $NoProperty
        )
        $domain = [ordered]@{ Name = 'contoso.com'; DomainMode = $Mode }
        if (-not $NoProperty) {
            $domain['ExpirePasswordsOnSmartCardOnlyAccounts'] = $Expire
        }
        $state = [PSCustomObject]@{ Domain = [PSCustomObject]$domain }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDomainSmartCardPasswordExpiration' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when the attribute is TRUE' {
            Use-Domain -Expire $true

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $true
        }

        It 'fails when the attribute is FALSE' {
            Use-Domain -Expire $false

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $false
        }

        It 'fails when the attribute is not set' {
            Use-Domain -Expire $null

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $false
        }

        It 'fails when the collector did not return the property at all' {
            Use-Domain -NoProperty

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $false
        }

        It 'fails for a value that is not a boolean TRUE' {
            Use-Domain -Expire 'TRUE'

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $false
        }

        It 'evaluates the Windows Server 2016 level and a newer level' {
            Use-Domain -Mode 10 -Expire $true

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -Be $true
        }
    }

    Context 'result text' {
        It 'names the domain when the attribute is TRUE' {
            Use-Domain -Expire $true

            $null = Test-MtAnssiAdDomainSmartCardPasswordExpiration

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is TRUE on contoso\.com'
            }
        }

        It 'says FALSE when the attribute is FALSE' {
            Use-Domain -Expire $false

            $null = Test-MtAnssiAdDomainSmartCardPasswordExpiration

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is FALSE on the root of the domain contoso\.com' -and
                $Result -notmatch 'is not set'
            }
        }

        It 'says not set when the attribute has no value' {
            Use-Domain -Expire $null

            $null = Test-MtAnssiAdDomainSmartCardPasswordExpiration

            Should -Invoke @detail -ParameterFilter {
                $Result -match 'is not set on the root of the domain contoso\.com' -and
                $Result -notmatch 'is FALSE'
            }
        }
    }

    Context 'data requested' {
        It 'reads the Domain category' {
            Use-Domain

            $null = Test-MtAnssiAdDomainSmartCardPasswordExpiration

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Domain' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped below the Windows Server 2016 level, even when the attribute is not set' {
            Use-Domain -Mode 'Windows2012R2Domain' -Expire $null

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'level is 6,' -and
                $SkippedCustomReason -match 'ANSSI-AD-017'
            }
        }

        It 'is skipped one level below Windows Server 2016' {
            Use-Domain -Mode 'Windows2012R2Domain' -Expire $true

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -BeNullOrEmpty
        }

        It 'is skipped when the functional level is not recognized' {
            Use-Domain -Mode 'unknown' -Expire $true

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'functional level'
            }
        }

        It 'is skipped when there is no domain in the collected data' {
            $state = [PSCustomObject]@{ Domain = $null }
            Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())

            Test-MtAnssiAdDomainSmartCardPasswordExpiration | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'not found'
            }
        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDomainSmartCardPasswordExpiration } | Should -Throw 'LDAP bind failed'

        }
    }
}
