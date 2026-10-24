Emergency access (break-glass) accounts must stay usable when everything else fails, so Conditional Access policies should not block them.

Maester evaluates a sign-in for up to five emergency access accounts (the ones set in `EmergencyAccessAccounts` in maester-config.json; if none are set, the users or group most often excluded from Conditional Access policies) with the Conditional Access What If API. One result is created per account (MT.1034.&lt;n&gt;). The check fails when any policy applies to the account.

### Remediation action:

1. Open the [Microsoft Entra admin center][ca-policies] and navigate to **Entra ID** >
   **Conditional Access** > **Policies**.
2. Open each Conditional Access policy that applies to the account, as listed in this section.
3. Under **Users** > **Exclude**, add the reported emergency access account, or the group that
   holds it. If a policy cannot be changed, document why the account is allowed to be blocked.
4. Confirm that the account is listed under `EmergencyAccessAccounts` in maester-config.json. If it
   is not an emergency access account, find out why it is excluded from the Conditional Access
   policies, then list the real emergency access accounts under `EmergencyAccessAccounts`.
5. Run the Conditional Access What If tool for the account and confirm that no policy applies.

### Related links

* [Manage emergency access accounts in Microsoft Entra ID][emergency-access]
* [Conditional Access What If tool][what-if]

[ca-policies]: https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies
[emergency-access]: https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
[what-if]: https://learn.microsoft.com/entra/identity/conditional-access/what-if-tool

<!--- Results --->
%TestResult%
