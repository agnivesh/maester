function Get-MtAnssiAdDnsAdminsReport {
    <#
    .SYNOPSIS
    Builds the verdict and the result text of the DnsAdmins group test.

    .DESCRIPTION
    The test passes when the group has no member and no principal outside the privileged set holds a
    dangerous right on it. Otherwise the text lists the members and the rights in two tables.

    .PARAMETER Member
    The member rows of the group, as returned by ConvertTo-MtAnssiAdGroupMemberRow.

    .PARAMETER Right
    The dangerous rights, as returned by Get-MtAnssiAdAceControl.

    .PARAMETER Principal
    The users, computers and groups that name the trustees of the rights.

    .PARAMETER Note
    The note about privileged members that could not be resolved, or an empty string.

    .EXAMPLE
    Get-MtAnssiAdDnsAdminsReport -Member $members -Right $rights -Principal $principal -Note ''

    Returns an object with Passed (bool) and Result (the text for the test result).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Member,

        [AllowEmptyCollection()]
        [object[]] $Right,

        [AllowNull()]
        [object[]] $Principal,

        [string] $Note
    )

    if ($Member.Count + $Right.Count -eq 0) {
        return [PSCustomObject]@{
            Passed = $true
            Result = 'DnsAdmins has no member and no principal outside the ' +
                "privileged set holds a dangerous right on it.$Note"
        }
    }

    $memberTable = ConvertTo-MtAnssiAdMarkdownTable -InputObject $Member `
        -Column ([ordered]@{ 'Member' = { $_.Member }; 'Kind' = { $_.Kind } })
    $rightTable = Format-MtAnssiAdAceControlTable -Row $Right -Principal $Principal
    return [PSCustomObject]@{
        Passed = $false
        Result = "DnsAdmins has $($Member.Count) members and " +
            "$($Right.Count) dangerous rights held outside the privileged set.$Note`n`n" +
            "#### Members`n`n$memberTable`n`n#### Dangerous rights`n`n$rightTable"
    }
}
