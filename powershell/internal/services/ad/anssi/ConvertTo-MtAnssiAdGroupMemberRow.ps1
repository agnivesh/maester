function ConvertTo-MtAnssiAdGroupMemberRow {
    <#
    .SYNOPSIS
    Lists the members of a group, as read by Get-MtAnssiAdGroupMemberAccount, as table rows.

    .DESCRIPTION
    Returns one row per member account (direct, nested or through its primary group), per nested
    group and per member outside the collected data, each with the member's distinguished name
    and its kind: Account, Group or Not collected. Rows are sorted by kind, then name.

    .PARAMETER Membership
    The result of Get-MtAnssiAdGroupMemberAccount.

    .EXAMPLE
    ConvertTo-MtAnssiAdGroupMemberRow -Membership $membership

    Returns rows with the Member and Kind properties.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Membership
    )

    $rows = @(
        $Membership.MemberDn | ForEach-Object {
            [PSCustomObject]@{ Member = $_; Kind = 'Account' }
        }
        $Membership.NestedGroup | ForEach-Object {
            [PSCustomObject]@{ Member = $_; Kind = 'Group' }
        }
        $Membership.Unresolved | ForEach-Object {
            [PSCustomObject]@{ Member = $_; Kind = 'Not collected' }
        }
    )
    return @($rows | Sort-Object -Property Kind, Member)
}
