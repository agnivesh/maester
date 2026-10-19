function Format-MtAnssiAdRodcRevealedTable {
    <#
    .SYNOPSIS
    Builds the table of privileged accounts whose secret is cached on a read-only domain controller.

    .DESCRIPTION
    One row per account and read-only domain controller, sorted by account name and then by
    controller name. The Domain column is read from the distinguished name of the account.

    .PARAMETER Finding
    The findings, as returned by Get-MtAnssiAdRodcRevealedAccount: each has an Account (with Item,
    Group and DistinguishedName) and a Controller (with Computer).

    .EXAMPLE
    Format-MtAnssiAdRodcRevealedTable -Finding $findings

    Returns the table as markdown text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object[]] $Finding
    )

    $sorted = @($Finding | Sort-Object -Property { $_.Account.Item.SamAccountName },
        { $_.Controller.Computer.Name })
    return ConvertTo-MtAnssiAdMarkdownTable -InputObject $sorted `
        -DomainSource { $_.Account.DistinguishedName } `
        -Column ([ordered]@{
            'Account'            = { $_.Account.Item.SamAccountName }
            'RODC'               = { $_.Controller.Computer.Name }
            'Privileged through' = { $_.Account.Group -join ', ' }
            'Password last set'  = { Format-MtAnssiAdDate $_.Account.Item.PasswordLastSet }
        })
}
