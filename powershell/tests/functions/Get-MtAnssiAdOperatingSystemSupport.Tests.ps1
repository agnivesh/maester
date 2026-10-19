BeforeAll {
    Import-Module "$PSScriptRoot/../../Maester.psd1" -Force
}

Describe 'Get-MtAnssiAdOperatingSystemSupport' {
    It '<Text> is <Name>, supported until <End>' -ForEach @(
        @{ Text = 'Windows 2000 Server'; Name = 'Windows 2000'; End = '2010-07-13' }
        @{ Text = 'Windows Server 2003'; Name = 'Windows Server 2003'; End = '2015-07-14' }
        @{ Text = 'Windows Server 2003 R2'; Name = 'Windows Server 2003'; End = '2015-07-14' }
        @{ Text = 'Windows Server 2008 Standard'; Name = 'Windows Server 2008'; End = '2020-01-14' }
        @{ Text = 'Windows Server 2008 R2 Enterprise'; Name = 'Windows Server 2008 R2'
            End = '2020-01-14' }
        @{ Text = 'Windows Server 2012 Datacenter'; Name = 'Windows Server 2012'
            End = '2023-10-10' }
        @{ Text = 'Windows Server 2012 R2 Standard'; Name = 'Windows Server 2012 R2'
            End = '2023-10-10' }
        @{ Text = 'Windows Server 2016 Standard'; Name = 'Windows Server 2016'; End = '2027-01-12' }
        @{ Text = 'Windows Server 2019 Datacenter'; Name = 'Windows Server 2019'
            End = '2029-01-09' }
        @{ Text = 'Windows Server 2022 Standard'; Name = 'Windows Server 2022'; End = '2031-10-14' }
        @{ Text = 'Windows Server 2025 Datacenter'; Name = 'Windows Server 2025'
            End = '2034-11-14' }
    ) {
        $result = InModuleScope Maester -Parameters @{ Text = $Text } {
            Get-MtAnssiAdOperatingSystemSupport -OperatingSystem $Text
        }

        $result.Name | Should -Be $Name
        $result.EndOfSupport.ToString('yyyy-MM-dd') | Should -Be $End
    }

    It 'reads the trademark forms stored by older versions' -ForEach @(
        @{ Text = 'Windows Server(R) 2008 R2 Standard' }
        @{ Text = ('Windows Server{0} 2008 R2 Standard' -f [char]0x00AE) }
        @{ Text = ('Windows Server{0} 2008 R2 Standard' -f [char]0x2122) }
        @{ Text = '  Windows   Server 2008 R2   Standard ' }
    ) {
        $result = InModuleScope Maester -Parameters @{ Text = $Text } {
            Get-MtAnssiAdOperatingSystemSupport -OperatingSystem $Text
        }

        $result.Name | Should -Be 'Windows Server 2008 R2'
    }

    It 'returns null for <Text>' -ForEach @(
        @{ Text = $null }
        @{ Text = '' }
        @{ Text = '   ' }
        @{ Text = 'Windows Server Datacenter' }
        @{ Text = 'Linux' }
        @{ Text = 'Samba Windows Server 2016' }
    ) {
        $result = InModuleScope Maester -Parameters @{ Text = $Text } {
            Get-MtAnssiAdOperatingSystemSupport -OperatingSystem $Text
        }

        $result | Should -BeNullOrEmpty
    }
}
