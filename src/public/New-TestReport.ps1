﻿<#
 .Synopsis
  Generates a formatted html report using the xml output from unit test frameworks like Pester.

 .Description
    The generated html is a single file that provides a visual representation of the test
    results with a summary view and click through of the details.

 .Example
  New-Testreport PesterResults $pesterResults -OutputHtmlPath ./testResults.html
#>

Function New-TestReport {
    [CmdletBinding()]
    param(
        # The Pester test results returned from Invoke-Pester -PassThru
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [psobject] $PesterResults,
        # The path to the html file to be generated
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string] $OutputHtmlPath
    )

    process {
        $mgContext = Get-MgContext

        $tenantId = $mgContext.TenantId
        $tenantName = '' #TODO: Get tenant name and other info like logo using Graph
        $account = $mgContext.Account

        $mtTests = @()
        foreach ($test in $PesterResults.Tests) {

            $name = $test.Name
            $helpUrl = ''

            $start = $name.IndexOf("See https")
            if ($start -gt 0) {
                $helpUrl = $name.Substring($start + 4).Trim() #Strip away the "See https://maester.dev" part
                $name = $name.Substring(0, $start).Trim() #Strip away the "See https://maester.dev" part
            }
            $mtTestInfo = [PSCustomObject]@{
                Name        = $name
                HelpUrl     = $helpUrl
                Tag         = $test.Tag
                Result      = $test.Result
                ScriptBlock = $test.ScriptBlock
                ErrorRecord = $test.ErrorRecord
                Duration    = $test.Duration
                Block       = $test.Block
            }
            $mtTests += $mtTestInfo
        }
        $mtTestResults = [PSCustomObject]@{
            Result       = $PesterResults.Result
            FailedCount  = $PesterResults.FailedCount
            PassedCount  = $PesterResults.PassedCount
            SkippedCount = $PesterResults.SkippedCount
            TotalCount   = $PesterResults.TotalCount
            ExecutedAt   = $PesterResults.ExecutedAt
            TenantId     = $tenantId
            TenantName   = $tenantName
            Account      = $account
            Tests        = $mtTests
        }
        $json = $mtTestResults | ConvertTo-Json -Depth 2 -WarningAction Ignore

        $htmlFilePath = Join-Path -Path $PSScriptRoot -ChildPath '../assets/ReportTemplate.html'
        $templateHtml = Get-Content -Path $htmlFilePath -Raw

        $insertLocationStart = $templateHtml.IndexOf("const testResults = {")
        $insertLocationEnd = $templateHtml.IndexOf("function TestResultsTable() {")

        $outputHtml = $templateHtml.Substring(0, $insertLocationStart)
        $outputHtml += "const testResults = $json;`n"
        $outputHtml += $templateHtml.Substring($insertLocationEnd)

        #write file
        Out-File -FilePath $OutputHtmlPath -InputObject $outputHtml -Encoding UTF8
    }

}