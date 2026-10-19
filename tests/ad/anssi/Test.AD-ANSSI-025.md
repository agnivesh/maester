This test checks that only privileged principals can control the DPAPI backup keys of the domain.

Windows protects many user secrets with DPAPI: passwords saved in browsers and the credential manager, mail and messaging tokens, certificate private keys, Wi-Fi passphrases. Each user's DPAPI keys are protected by the user's password, and also by a domain backup key so that they can be recovered when the password is reset. The domain backup keys are stored in Active Directory as `BCKUPKEY` secret objects in the System container. Whoever can take control of these objects can work towards reading the backup keys and, from them, decrypt the DPAPI data of every user of the domain. DPAPI itself is not the weakness here; the permissions on its keys are.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns a backup key object, or holds full control, all extended rights, the right to change its permissions or owner, to write all its attributes, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right on it | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Bring the objects listed in the results back to their default permissions, for example with ADSI Edit or `dsacls`. By default only Local System has rights on these objects. Changing their permissions is not needed for any normal operation.

#### How the test works

The test reads, one level below `CN=System` of the domain, the secret objects whose name starts with `BCKUPKEY`, with their owner and permissions. It works out the privileged set as the other ANSSI permission tests do: the groups Active Directory protects with AdminSDHolder, their members (nested and through primary groups), the groups walked to find them, and a few system principals Windows trusts by default. It reports each right from a fixed list held by a principal outside that set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too. The backup key values are read only by domain controllers; reading them needs extended rights, which the list covers.

Some things are not checked:

- the DPAPI data of the users and the computers themselves;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

The scan account usually needs administrator rights to see these objects. If no backup key object is found, if one of them cannot be read, or if a read fails, the test is skipped rather than reporting a result.

#### Rights held by Exchange groups

If Exchange was installed with its default setup (the shared permissions model), its security groups Exchange Trusted Subsystem, Exchange Windows Permissions, Organization Management and Exchange Servers hold wide rights in the directory, mostly on the domain object, and many objects inherit them. These groups are not part of the privileged set, so this test reports their rights. That is intended: attackers have used these rights to take over accounts and, in the 2019 PrivExchange attack, to reach Domain Admin. The Exchange updates of 2019 removed the worst of it, the right to change permissions on the domain object itself, but SpecterOps showed in 2024 that the shared model still lets these groups take over any user or group that inherits permissions from the domain object. When a result lists one of these groups, it adds a note with the cause and the remedy.

The usual remedy is to switch Exchange to Active Directory split permissions, which removes the entries Exchange adds for its security groups on the domain object, or to move those entries from the domain object to the organizational units Exchange manages. Test the change first: Exchange administrators lose some tasks, such as creating users from the Exchange tools.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose DPAPI key objects](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_dpapi)
- [Microsoft Learn: Split permissions in Exchange Server](https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions)
- [Dirk-Jan Mollema: Abusing Exchange, one API call away from Domain Admin (PrivExchange, 2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CERT-EU: Privilege Escalation Exploiting MS Exchange (security advisory 2019-002)](https://cert.europa.eu/publications/security-advisories/2019-002/pdf)
- [SpecterOps: Pwned by the Mail Carrier (Exchange permissions in Active Directory, 2024)](https://specterops.io/blog/2024/03/20/pwned-by-the-mail-carrier/)

<!--- Results --->

%TestResult%
