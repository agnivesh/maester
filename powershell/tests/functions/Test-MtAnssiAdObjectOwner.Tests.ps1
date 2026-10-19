BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-058.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdObjectOwner' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdObjectOwner {
        InModuleScope Maester { Test-MtAnssiAdObjectOwner }
    }

    $script:detail = @{
        CommandName = 'Add-MtTestResultDetail'
        ModuleName  = 'Maester'
        Times       = 1
        Exactly     = $true
    }
    $script:now = [datetime]::SpecifyKind([datetime]'2026-06-15T12:00:00', 'Utc')

    function Get-Object {
        param(
            [string] $Name,
            [AllowNull()] [string] $Owner = 'S-1-5-21-1-2-3-512',
            [datetime] $Created = [datetime]'2025-01-01'
        )
        [PSCustomObject]@{ Name = $Name; OwnerSid = $Owner; Created = $Created }
    }

    function Use-Ad {
        param(
            [object[]] $Object = @(Get-Object -Name 'a'),
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3'
        )
        $domainSidValue = $null
        if ($DomainSid) { $domainSidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{ DomainSID = $domainSidValue }
            Users            = @([PSCustomObject]@{
                    DistinguishedName = 'CN=helpdesk,DC=x'; Name = 'helpdesk'
                    Sid               = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1105' }
                })
            Computers        = @()
            Groups           = @()
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $objects = $Object
        Mock Get-MtAnssiAdObjectOwner -ModuleName Maester -MockWith ({ $objects }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdObjectOwner' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
        Mock Get-Date -ModuleName Maester -MockWith { $script:now }
    }

    Context 'verdict' {
        It 'passes when every object older than 7 days has an expected owner' {
            Use-Ad -Object @(
                Get-Object -Name 'a'
                Get-Object -Name 'new' -Owner 'S-1-5-21-1-2-3-1105' -Created $script:now.AddDays(-1)
            )

            Test-MtAnssiAdObjectOwner | Should -Be $true

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^None of the 2 users, computers, groups, organizational units'
            }
        }

        It 'fails when an object older than 7 days has an unexpected owner' {
            Use-Ad -Object @(
                Get-Object -Name 'a'
                Get-Object -Name 'b' -Owner 'S-1-5-21-1-2-3-1105'
                Get-Object -Name 'c' -Owner 'S-1-5-21-1-2-3-1105'
            )

            Test-MtAnssiAdObjectOwner | Should -Be $false

            Should -Invoke @detail -ParameterFilter {
                $Result -match '^2 object\(s\) older than 7 days are owned by 1 owner\(s\)'
            }
        }
    }

    Context 'result text' {
        It 'lists each owner with its name, SID, object count and examples' {
            Use-Ad -Object @(
                Get-Object -Name 'b' -Owner 'S-1-5-21-1-2-3-1105'
                Get-Object -Name 'c' -Owner 'S-1-5-21-1-2-3-1105'
                Get-Object -Name 'd' -Owner 'S-1-5-21-1-2-3-4444'
                Get-Object -Name 'e' -Owner $null
            )

            $null = Test-MtAnssiAdObjectOwner

            Should -Invoke @detail -ParameterFilter {
                $text = $Result -replace '\\', ''
                $text -match ('(?s)helpdesk \| S-1-5-21-1-2-3-1105 \| 2 \| b, c \|.*' +
                    '\|  \|  \| 1 \| e \|.*\|  \| S-1-5-21-1-2-3-4444 \| 1 \| d \|')
            }
        }

        It 'escapes markdown in an object name' {
            $name = '[click](https://evil.example)|x'
            Use-Ad -Object @(Get-Object -Name $name -Owner 'S-1-5-21-1-2-3-9')

            $null = Test-MtAnssiAdObjectOwner

            Should -Invoke @detail -ParameterFilter {
                $Result -notmatch [regex]::Escape('[click](https://evil.example)') -and
                $Result -notmatch [regex]::Escape('evil.example)|x')
            }
        }
    }

    Context 'data read' {
        It 'reads the owners through the collected connection details' {
            Use-Ad

            $null = Test-MtAnssiAdObjectOwner

            Should -Invoke Get-MtAnssiAdObjectOwner -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter { $ProtocolEvidence.ResolvedServer -eq 'dc1' }
        }

        It 'reads the Domain, Users, Computers and Groups categories' {
            Use-Ad

            $null = Test-MtAnssiAdObjectOwner

            Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly `
                -ParameterFilter {
                @($Categories).Count -eq 4 -and $Categories -contains 'Domain' -and
                $Categories -contains 'Users' -and $Categories -contains 'Computers' -and
                $Categories -contains 'Groups'
            }
        }
    }

    Context 'test cannot run' {
        It 'is skipped without reading when the domain SID is missing' {
            Use-Ad -DomainSid $null

            Test-MtAnssiAdObjectOwner | Should -BeNullOrEmpty

            Should -Invoke Get-MtAnssiAdObjectOwner -ModuleName Maester -Times 0 -Exactly
            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID'
            }
        }

        It 'is skipped when no object is found' {
            Use-Ad -Object @()

            Test-MtAnssiAdObjectOwner | Should -BeNullOrEmpty

            Should -Invoke @detail -ParameterFilter {
                $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'No user, computer'
            }
        }

        It 'lets the exception reach the engine when the owners cannot be read' {
            Use-Ad
            Mock Get-MtAnssiAdObjectOwner -ModuleName Maester `
                -MockWith { throw 'LDAP search failed' }

            { Test-MtAnssiAdObjectOwner } | Should -Throw 'LDAP search failed'

        }

        It 'lets the exception reach the engine when reading the AD state fails' {
            Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'LDAP bind failed' }

            { Test-MtAnssiAdObjectOwner } | Should -Throw 'LDAP bind failed'

        }
    }
}
