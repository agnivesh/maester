This test checks that no more than 25% of the enabled user and computer accounts of the domain are dormant.

A dormant account is an enabled account that meets both of the following conditions:

- its password was last set more than three years ago;
- it has not authenticated against the Active Directory for more than a year, or it was created more than a year ago and has never authenticated.

Dormant accounts are either legitimate accounts that are rarely used, or obsolete accounts. Obsolete accounts grant illegitimate access, for example to someone who has left the company, and an attacker can use them stealthily, which is even more problematic if the accounts are privileged. Their mere existence also makes user and access rights accountability much harder.

#### What ANSSI says and how it rates the risk

ANSSI raises this finding when more than 25% of the accounts of the forest are dormant: enabled accounts whose password is more than three years old and that have not authenticated for more than a year. It says obsolete accounts give illegitimate access and make accountability harder.

ANSSI rates it level 1. Maester rates it Low: dormant accounts are an identity hygiene problem that raises exposure, not an attack path on its own.

#### Remediation action

Without an account management policy, obsolete accounts can remain in the domain for extended periods, for example after a person leaves the company or changes roles, or after an application or a computer is retired. Obsolete accounts (computer, user, administrator or service accounts alike) must be disabled, or even deleted.

Obsolete accounts must be distinguished from the other dormant accounts. Some dormant accounts are legitimate, such as accounts used in case of emergency, or functional Exchange accounts used to create mailboxes read through access delegations. Such accounts should be disabled and put in a dedicated OU.

To disable an unused account properly, which gives similar benefits to deleting it while keeping the information relevant to audit traces:

1. disable the account;
2. remove all of its group memberships;
3. randomly change its password; checking "smart card is required for interactive logon" in the account properties enforces a random password;
4. optionally, move the account to a dedicated OU;
5. optionally, update the description of the account with the context for disabling (date, reason, and so on).

#### How the test works

The test reads the user and computer accounts of the domain and keeps the enabled ones. An account is dormant when its `pwdLastSet` is more than three years old (or the password was never set) and its `lastLogonTimestamp` is more than a year old. An account that never authenticated is dormant when it was created more than a year ago. The test fails when more than 25% of the enabled accounts are dormant.

The `lastLogonTimestamp` attribute is only updated when the domain functional level is recent enough, so accounts of a very old domain can appear dormant when they are not.

The results list the dormant accounts with the oldest password first, up to 100 accounts.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

If the read of the users or computers fails, the domain controller returns nothing for them and the test is skipped. It does not pass on an empty list.

#### Related links

- [ANSSI Active Directory checkpoints: Dormant accounts](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_user_accounts_dormant)

<!--- Results --->

%TestResult%
