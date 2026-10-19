BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    # A native test is not part of the module: define its function in the module scope so that
    # the mocks of the internal helpers apply, and call it through a proxy of the same name.
    $script:testFile = "$PSScriptRoot/../../../tests/ad/anssi/Test.AD-ANSSI-005.ps1"
    InModuleScope Maester -Parameters @{ Path = $script:testFile; Name = 'Test-MtAnssiAdCriticalObjectAvailable' } {
        param($Path, $Name)
        $text = (Get-Content -LiteralPath $Path -Raw) -replace "function $Name", "function script:$Name"
        Invoke-Expression $text
    }

    function Test-MtAnssiAdCriticalObjectAvailable {
        InModuleScope Maester { Test-MtAnssiAdCriticalObjectAvailable }
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
            [AllowNull()] [string] $DomainSid = 'S-1-5-21-1-2-3',
            [AllowNull()] [string] $DomainDn = 'DC=x'
        )
        $sidValue = $null
        if ($DomainSid) { $sidValue = [PSCustomObject]@{ Value = $DomainSid } }
        $state = [PSCustomObject]@{
            Domain = [PSCustomObject]@{ DomainSID = $sidValue; DistinguishedName = $DomainDn }
            Users  = @(); Groups = @()
        }
        Mock Get-MtADDomainState -ModuleName Maester -MockWith ({ $state }.GetNewClosure())
        $findingList = $Finding
        Mock Get-MtAnssiAdCriticalObject -ModuleName Maester `
            -MockWith ({ $findingList }.GetNewClosure())
    }
}

Describe 'Test-MtAnssiAdCriticalObjectAvailable' {
    BeforeEach {
        Mock Add-MtTestResultDetail -ModuleName Maester { }
    }

    It 'passes when every critical object is found and readable' {
        Use-Ad

        Test-MtAnssiAdCriticalObjectAvailable | Should -Be $true

        Should -Invoke @detail -ParameterFilter {
            $Result -eq 'Every critical object was found and its permissions read.'
        }
        Should -Invoke Get-MtADDomainState -ModuleName Maester -Times 1 -Exactly -ParameterFilter {
            @($Categories).Count -eq 3 -and $Categories -contains 'Domain' -and
            $Categories -contains 'Users' -and $Categories -contains 'Groups'
        }
        Should -Invoke Get-MtAnssiAdCriticalObject -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            $AdState.Domain.DistinguishedName -eq 'DC=x'
        }
    }

    It 'fails and lists the objects with a problem' {
        Use-Ad -Finding @(
            [PSCustomObject]@{
                Object = 'krbtgt (RID 502)'; DistinguishedName = 'CN=krbtgt,DC=x'
                Problem = 'Permissions not readable'
            }
            [PSCustomObject]@{
                Object = 'Administrator (RID 500)'; DistinguishedName = ''
                Problem = 'Not found in the collected data'
            }
        )

        Test-MtAnssiAdCriticalObjectAvailable | Should -Be $false

        Should -Invoke @detail -ParameterFilter {
            $Result -match '^2 critical objects are missing or cannot be read' -and
            $Result -match
            '\| krbtgt \\\(RID 502\\\) \| CN=krbtgt,DC=x \| Permissions not readable \|' -and
            $Result -match
            '\| Administrator \\\(RID 500\\\) \|  \| Not found in the collected data \|'
        }
    }

    It 'lets the exception reach the engine when the state cannot be read' {
        Mock Get-MtADDomainState -ModuleName Maester -MockWith { throw 'boom' }

        { Test-MtAnssiAdCriticalObjectAvailable } | Should -Throw

    }

    It 'skips when the domain <Name> is missing' -ForEach @(
        @{ Name = 'SID'; Sid = $null; Dn = 'DC=x' }
        @{ Name = 'name'; Sid = 'S-1-5-21-1-2-3'; Dn = $null }
    ) {
        Use-Ad -DomainSid $Sid -DomainDn $Dn

        $null -eq (Test-MtAnssiAdCriticalObjectAvailable) | Should -Be $true

        Should -Invoke @detail -ParameterFilter {
            $SkippedBecause -eq 'Custom' -and $SkippedCustomReason -match 'domain SID or name'
        }
        Should -Invoke Get-MtAnssiAdCriticalObject -ModuleName Maester -Times 0 -Exactly
    }

    It 'lets the exception reach the engine when a read fails' {
        Use-Ad
        Mock Get-MtAnssiAdCriticalObject -ModuleName Maester -MockWith { throw 'no such object' }

        { Test-MtAnssiAdCriticalObjectAvailable } | Should -Throw '*no such object*'

    }
}
