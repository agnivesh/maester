function Get-MtAnssiAdSidHistoryObject {
    <#
    .SYNOPSIS
    Finds the users, computers and groups that have a SID history.

    .DESCRIPTION
    Returns one object for each user, computer or group whose sIDHistory attribute holds at least
    one value. The values are converted to SID strings, whether the collector returned text, a
    SecurityIdentifier or, outside Windows, an object with a Value property.

    Disabled accounts are returned too: the attribute is a leftover of a migration whatever the
    state of the account.

    .PARAMETER User
    The user accounts, as collected for the Users category.

    .PARAMETER Computer
    The computer accounts, as collected for the Computers category.

    .PARAMETER Group
    The groups, as collected for the Groups category.

    .EXAMPLE
    Get-MtAnssiAdSidHistoryObject -User $users -Computer $computers -Group $groups

    Returns one object with Type, Name, SidHistory and LastLogonDate for each object found.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $User,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Computer,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Group
    )

    # The leading commas keep each pair an array instead of letting the outer array flatten it.
    $sources = @(
        , @('User', $User)
        , @('Computer', $Computer)
        , @('Group', $Group)
    )

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($source in $sources) {
        foreach ($item in $source[1]) {
            $values = foreach ($sid in $item.SidHistory) {
                $text = [string]$sid
                if ($null -ne $sid.PSObject.Properties['Value']) { $text = [string]$sid.Value }
                $text
            }
            if (@($values).Count -eq 0) { continue }

            $found.Add([PSCustomObject]@{
                    Type          = $source[0]
                    Name          = $item.SamAccountName
                    SidHistory    = @($values)
                    LastLogonDate = $item.LastLogonDate
                })
        }
    }

    Write-Verbose "Objects with a SID history: $($found.Count)"
    return $found.ToArray()
}
