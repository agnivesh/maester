This test checks that the computer accounts of Windows server clusters have had their password renewed within the last 3 years.

A failover cluster has a computer account for the cluster itself, the cluster name account, and for most clustered services and applications. Their secrets must be renewed from time to time. A password that has not changed for years gives a long time to an attacker who has obtained it, for example from a copy of the account database or from a former administrator.

#### Remediation action

Renew the password of the computer accounts used by the cluster at least every 3 years.

The renewal must follow a specific process that depends on the cluster members. Give the administrators of the cluster the Reset password permission on the cluster name account in advance. When the password of the account no longer matches the one stored by the clustering software, take the cluster name resource offline and use the Repair Active Directory Object action of Failover Cluster Manager. The Microsoft articles below describe the process.

#### How the test works

The test treats a computer account as a cluster account when one of its service principal names starts with `MSClusterVirtualServer/`. The cluster name account and the accounts of clustered services and applications carry this name. This is how the test recognizes cluster accounts: Microsoft documents these accounts as computer accounts but does not document this service principal name, so check on your own clusters that the accounts you expect are listed or skipped as intended. It ignores the disabled accounts. It fails when the `pwdLastSet` attribute of an enabled cluster account is more than 3 years old, or when the password was never set.

The nodes of a cluster are ordinary servers and are checked by ANSSI-AD-060, ANSSI-AD-046 and ANSSI-AD-059, not by this test. Cluster accounts are left out of those tests and are checked here with a limit of 3 years.

The test is skipped when no enabled cluster account is in the collected data.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Windows server cluster accounts with passwords unchanged for more than 3 years](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_password_change_cluster_no_change_3years)
- [Microsoft: Failover cluster accounts overview, planning ahead for password resets](https://learn.microsoft.com/windows-server/failover-clustering/failover-cluster-accounts-overview#planning-ahead-for-password-resets-and-other-account-maintenance)
- [Microsoft: Troubleshoot password issues with the cluster name account](https://learn.microsoft.com/troubleshoot/windows-server/high-availability/troubleshoot-issues-accounts-used-failover-clusters#troubleshoot-password-issues-with-the-cluster-name-account)

<!--- Results --->

%TestResult%
