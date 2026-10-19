BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force

    $script:domainSid = 'S-1-5-21-1-2-3'

    function Get-PrincipalFixture {
        param([string] $Name, [string] $Rid)
        [PSCustomObject]@{
            DistinguishedName = "CN=$Name,DC=x"
            Sid               = [PSCustomObject]@{ Value = "$script:domainSid-$Rid" }
        }
    }

    function Get-Critical {
        param([string[]] $Rid = @('500', '502', '512', '518', '519'), [string] $Forest = 'x.com',
            [string[]] $Unreadable = @())
        $users = @()
        $groups = @()
        foreach ($value in $Rid) {
            $item = Get-PrincipalFixture -Name "o$value" -Rid $value
            if ($value -in '500', '502') { $users += $item } else { $groups += $item }
        }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID = [PSCustomObject]@{ Value = $script:domainSid }
                DistinguishedName = 'DC=x'; DnsRoot = 'x.com'; Forest = $Forest
            }
            Users            = $users
            Groups           = $groups
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }
        $script:unreadableDn = $Unreadable
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith {
            foreach ($dn in $DistinguishedName) {
                $ace = @()
                if ($dn -in $script:unreadableDn) { $ace = $null }
                [PSCustomObject]@{ DistinguishedName = $dn; Ace = $ace }
            }
        }
        InModuleScope Maester -Parameters @{ State = $state } {
            param($State)
            @(Get-MtAnssiAdCriticalObject -AdState $State)
        }
    }

    function Format-Row {
        param([object[]] $Row)
        @($Row | ForEach-Object { "$($_.Object)|$($_.DistinguishedName)|$($_.Problem)" }) -join ';'
    }
}

Describe 'Get-MtAnssiAdCriticalObject' {
    It 'returns nothing when every object of the forest root domain is found and readable' {
        @(Get-Critical).Count | Should -Be 0

        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            ($DistinguishedName -join ';') -eq ('CN=AdminSDHolder,CN=System,DC=x;' +
                'CN=o500,DC=x;CN=o502,DC=x;' +
                'CN=o512,DC=x;CN=o518,DC=x;CN=o519,DC=x') -and
                    $ProtocolEvidence.ResolvedServer -eq 'dc1'
        }
    }

    It 'leaves out Schema Admins and Enterprise Admins in a child domain' {
        @(Get-Critical -Rid @('500', '502', '512') -Forest 'root.com').Count | Should -Be 0

        Should -Invoke Get-MtAnssiAdObjectSecurity -ModuleName Maester -Times 1 -Exactly `
            -ParameterFilter {
            @($DistinguishedName).Count -eq 4
        }
    }

    It 'reports objects missing from the collected data' {
        $result = Get-Critical -Rid @('502', '518')

        Format-Row -Row $result |
            Should -BeExactly ('Administrator (RID 500)||Not found in the collected data;' +
            'Domain Admins (RID 512)||Not found in the collected data;' +
            'Enterprise Admins (RID 519)||Not found in the collected data')
    }

    It 'reports objects whose permissions cannot be read, AdminSDHolder included' {
        $result = Get-Critical -Unreadable @('CN=AdminSDHolder,CN=System,DC=x', 'CN=o502,DC=x')

        Format-Row -Row $result |
            Should -BeExactly ('AdminSDHolder|CN=AdminSDHolder,CN=System,DC=x|' +
            'Permissions not readable;krbtgt (RID 502)|CN=o502,DC=x|Permissions not readable')
    }

    It 'lets a failed read throw' {
        Mock Get-MtAnssiAdObjectSecurity -ModuleName Maester -MockWith { throw 'no such object' }
        $state = [PSCustomObject]@{
            Domain           = [PSCustomObject]@{
                DomainSID         = [PSCustomObject]@{ Value = $script:domainSid }
                DistinguishedName = 'DC=x'
            }
            Users            = @(); Groups = @()
            ProtocolEvidence = [PSCustomObject]@{ ResolvedServer = 'dc1' }
        }

        { InModuleScope Maester -Parameters @{ State = $state } {
                param($State)
                Get-MtAnssiAdCriticalObject -AdState $State
            } } | Should -Throw -ExpectedMessage 'no such object'
    }
}
