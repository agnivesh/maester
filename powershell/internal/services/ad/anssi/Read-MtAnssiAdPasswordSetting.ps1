function Read-MtAnssiAdPasswordSetting {
    <#
    .SYNOPSIS
    Reads the length and age settings of one password settings object (PSO).

    .DESCRIPTION
    Reads the name, msDS-MinimumPasswordLength and msDS-MaximumPasswordAge of a fine-grained
    password policy with a base-scope LDAP search. Throws when the object or its minimum length
    (a mandatory attribute) does not come back, which happens when the reading account is not
    allowed to read password settings objects: an unreadable policy is never guessed.

    .PARAMETER Connection
    The LDAP connection to use.

    .PARAMETER DistinguishedName
    The distinguished name of the password settings object.

    .EXAMPLE
    Read-MtAnssiAdPasswordSetting -Connection $connection -DistinguishedName $psoDn

    Returns an object with Source, MinLength and MaxAge (a timespan, or $null for never).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection] $Connection,

        [Parameter(Mandatory)]
        [string] $DistinguishedName
    )

    $entry = Invoke-MtLdapSearch -Connection $Connection -SearchBase $DistinguishedName `
        -Scope Base -PageSize 0 `
        -Attributes @('name', 'msDS-MinimumPasswordLength', 'msDS-MaximumPasswordAge') |
        Select-Object -First 1
    if ($null -eq $entry.'msDS-MinimumPasswordLength') {
        throw ("The password settings object '$DistinguishedName' could not be read. Run the " +
            'test with an account allowed to read password settings objects.')
    }

    return [PSCustomObject]@{
        Source    = "Fine-grained policy $($entry.name)"
        MinLength = $entry.'msDS-MinimumPasswordLength'
        MaxAge    = $entry.'msDS-MaximumPasswordAge'
    }
}
