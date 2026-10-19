This test checks that authenticated users cannot join computers to the domain on their own, that is that the `ms-DS-MachineAccountQuota` attribute of the domain root is 0.

By default, authenticated users may join up to 10 computers to the domain. This value is controlled by the `ms-DS-MachineAccountQuota` attribute of the domain root object.

The computer accounts added this way are owned by the account that was used to create them, which gives that account full control over them. The vulnerability CVE-2021-42287 used such a computer account to elevate privileges.

#### Remediation action

Set the `ms-DS-MachineAccountQuota` attribute to 0 on the root object of the domain. This is usually done with `dsa.msc` or `adsiedit.msc`, or with PowerShell:

```powershell
Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota" = "0"}
```

Before doing so, delegate the right to create computer accounts to the accounts that need it, for example through a permission on a dedicated OU.

#### How the test works

The test reads `ms-DS-MachineAccountQuota` from the domain object. It fails when the value is not 0. When the attribute is not set, the default of 10 applies, so the test fails and says so.

#### Related links

- [ANSSI Active Directory checkpoints: Unrestricted domain join](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_user_accounts_machineaccountquota)

<!--- Results --->

%TestResult%
