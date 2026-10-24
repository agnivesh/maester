It is recommended to have at least one emergency/break glass account or account group excluded from all Conditional Access policies.
This allows for emergency access to the tenant in case of a misconfiguration or other issues.
Maester does not guess these accounts: they must be listed under `EmergencyAccessAccounts` in maester-config.json, and the test is skipped when none are listed.

See [Manage emergency access accounts in Microsoft Entra ID - Microsoft Learn](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)

<!--- Results --->
%TestResult%