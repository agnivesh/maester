Checks if the Conditional Access Policies for blocking legacy authentication is active and used.

Maester evaluates up to five member users (the emergency access accounts set in `EmergencyAccessAccounts` in maester-config.json are excluded; the test is skipped when none are set) with the Conditional Access What If API and creates one result per user (MT.1033.&lt;n&gt;).

See [Block legacy authentication - Microsoft Learn](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)

#### Remediation action

Create a Conditional Access policy that blocks legacy authentication for all users, excluding your emergency access accounts.

<!--- Results --->
%TestResult%
