BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-012.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdDisplaySpecifierScript' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdDisplaySpecifierScript {
        InModuleScope Maester { Test-MtAnssiAdDisplaySpecifierScript }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }

    function Get-Specifier {
        param([string] $Name = 'user-Display', [string[]] $Admin = @())
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=x"
            Name              = $Name
            AdminContextMenu  = $Admin
            ShellContextMenu  = @()
        }
    }

    function Use-Ad {
        param([object[]] $Specifier = @(Get-Specifier))
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ Name = 'contoso' }
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $specifiers = $Specifier
        Mock Get-MtAnssiAdDisplaySpecifier -ModuleName Maester `
            -MockWith ({ $specifiers }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdDisplaySpecifierScript' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    Context 'verdict' {
        It 'passes when no display specifier runs a program from a file share' {
            Use-Ad -Specifier @(Get-Specifier; Get-Specifier -Name 'group-Display')

            Test-MtAnssiAdDisplaySpecifierScript | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -eq ('None of the 2 display specifiers runs a program from a file server ' +
                    'outside SYSVOL.')
            }
        }

        It 'passes but lists the entries that run a program from SYSVOL' {
            Use-Ad -Specifier @(Get-Specifier -Admin '1,&A,\\contoso.com\SYSVOL\a.cmd')

            Test-MtAnssiAdDisplaySpecifierScript | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '1 context menu entries run one from SYSVOL or NETLOGON' -and
                $text -match 'user-Display \(409\) \| adminContextMenu \|'
            }
        }

        It 'fails when a display specifier runs a program from a file server outside SYSVOL' {
            Use-Ad -Specifier @(Get-Specifier -Admin '1,&A,\\fs1\tools\a.vbs')

            Test-MtAnssiAdDisplaySpecifierScript | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^1 context menu entries of the display specifiers run a' -and
                $text -match 'adminContextMenu \| fs1toolsa\.vbs \| File server'
            }
        }
    }

    Context 'result text' {
        It 'lists file server entries before SYSVOL ones, then by specifier' {
            Use-Ad -Specifier @(
                Get-Specifier -Name 'zz-Display' -Admin '1,&A,\\fs1\tools\z.vbs'
                Get-Specifier -Name 'aa-Display' -Admin '1,&A,\\contoso.com\NETLOGON\a.cmd'
                Get-Specifier -Name 'mm-Display' -Admin '1,&A,\\fs2\tools\m.vbs'
            )

            $null = Test-MtAnssiAdDisplaySpecifierScript

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match '^2 context menu entries' -and
                $text -match ('(?s)mm-Display \(409\).*File server.*zz-Display \(409\).*' +
                    'File server.*aa-Display \(409\).*SYSVOL')
            }
        }

        It 'escapes markdown in a program path' {
            Use-Ad -Specifier @(Get-Specifier -Admin '1,&A,\\fs1\[click](https://evil.example)|x')

            $null = Test-MtAnssiAdDisplaySpecifierScript

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data read' {
        It 'reads the display specifiers through the collected connection details' {
            Use-Ad

            $null = Test-MtAnssiAdDisplaySpecifierScript

            Should -Invoke Get-MtAnssiAdDisplaySpecifier -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { @($Categories).Count -eq 1 -and $Categories -contains 'Domain' }
        }
    }

    Context 'test cannot run' {
        It 'is skipped when no display specifier is found' {
            Use-Ad -Specifier @()

            Test-MtAnssiAdDisplaySpecifierScript | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'No display specifier'
            }
        }

        It 'lets the exception reach the engine when the display specifiers cannot be read' {
            Use-Ad
            Mock Get-MtAnssiAdDisplaySpecifier -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdDisplaySpecifierScript } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdDisplaySpecifierScript } | Should -Throw 'LDAP bind failed'

        }
    }
}
