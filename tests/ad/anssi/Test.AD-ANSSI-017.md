This test checks that the forest functional level is at least Windows Server 2016.

Functional levels are set at the forest and at the domain level, and each level turns on security features of Active Directory. A low functional level deprives the forest of these features. The levels are numbered from 0 (Windows 2000) to 7 (Windows Server 2016), and each one brings:

- level 2 (Windows Server 2003): forest trusts and read-only domain controller (RODC) support;
- level 3 (Windows Server 2008): modern cryptographic algorithms such as AES, and DFS replication (DFSR) for the SYSVOL share;
- level 4 (Windows Server 2008 R2): the Active Directory Recycle Bin, which protects objects against accidental deletion;
- level 5 (Windows Server 2012): advanced Kerberos features such as compound authentication and claims;
- level 6 (Windows Server 2012 R2): authentication policies, authentication policy silos and the Protected Users group;
- level 7 (Windows Server 2016): an upgraded smart card logon security and Privileged Identity Management (PIM) trust relationships between forests.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

The severity depends on the forest functional level. The result table shows the severity that applies to each finding.

| Forest functional level | ANSSI level | Severity |
| --- | --- | --- |
| Below Windows Server 2008 R2 (level 4) | 1 | Critical |
| Below Windows Server 2012 R2 (level 6) | 3 | Medium |
| Below Windows Server 2016 (level 7) | 4 | Low |

#### Remediation action

Raise the functional levels to the highest value that all domain controllers support. To raise a domain functional level, all of its domain controllers must run an operating system that supports the desired level. To raise the forest functional level, all of its domains must first be at the same level or higher.

```powershell
Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain
Set-ADForestMode -Identity <forest> -ForestMode Windows2016Forest
```

Before raising a level, check the compatibility of the third-party software with the target level. The Exchange Server supportability matrix is an example of software that can limit the supported functional levels.

#### How the test works

The test reads the forest functional level from the collected data and compares it with the thresholds above. The test passes when the forest is at level 7 (Windows Server 2016) or higher, which includes Windows Server 2025. The functional level of the domain is shown for information.

When the forest functional level is not in the collected data, the test is skipped because it is unknown.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Insufficient forest and domains functional levels](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_functional_level)
- [Microsoft Learn: Active Directory Domain Services functional levels](https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels)
- [Microsoft Learn: Raise domain and forest functional levels](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/raise-domain-forest-functional-levels)
- [Microsoft Learn: Exchange Server supportability matrix](https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix)

<!--- Results --->

%TestResult%
