This test checks that only privileged principals can control the schema of the forest.

The schema defines every class and attribute that Active Directory can hold, including the default permissions given to each new object of a class. Whoever can change a class definition can, for example, add themselves to the default permissions of every user, group or computer created from then on, or change how an attribute is handled. Whoever can create schema objects can add classes and attributes of their own. These changes reach the whole forest and are hard to undo. By default only Schema Admins can change the schema.

#### Severity levels

In the Maester report the severity of this test is always Critical, the most severe level it can raise (Maester 3.0 uses the declared severity for the whole test). The Severity column of the results shows the level of each finding.

| Condition | ANSSI level | Maester severity |
| --- | --- | --- |
| A principal outside the privileged set owns the schema container or a schema object, or holds full control, the right to change its permissions or owner, to write all its attributes, or another right usable without a major prerequisite | 1 | Critical |
| A principal outside the privileged set holds another potentially dangerous right, such as creating objects in the schema container | 2 | High |

A passing result is reported with the most severe level the test can raise, Critical.

#### Remediation action

Bring the objects listed in the results back to their default permissions, for example with ADSI Edit, or with `dsacls <DN> /S /T`. Changes to schema permissions are expected only when the forest functional level is raised or when a product extends the schema, and should be reverted afterwards. Keep Schema Admins empty except during such changes.

#### How the test works

The test reads the RootDSE to find the schema naming context, reads the owner and permissions of the schema container, and searches one level below it for every class and attribute definition. It works out the privileged set as the other ANSSI permission tests do; Schema Admins and Enterprise Admins of the forest root domain are part of it. It reports each right from a fixed list held by a principal outside that set, unless an earlier deny entry for the same principal, Everyone or Authenticated Users takes it away. An owner outside the privileged set is reported too.

Some things are not checked:

- the default security descriptors stored in the class definitions (the permissions new objects will get), which would need an SDDL parser;
- deny entries for other groups, which can only make the test report more than needed;
- members of the protected groups that live outside the collected domain. The results say how many there were.

These objects belong to the whole forest. The test takes the SID of the forest root domain from the domain itself, or, in a child domain, from the trust to the parent domain, and trusts that domain's Domain Admins, Domain Controllers, Read-only Domain Controllers and Key Admins groups, as it does for the domain it runs in, so that running it from a child domain does not report the default permissions of the forest root. The Domain Admins group of the domain the test runs in stays trusted as well, so a right held by it on these objects is not reported. If the SID of the forest root domain cannot be found, for example in a grandchild domain, which has no trust to the root, the test is skipped.

If a read fails, or the permissions of an object cannot be read, the test is skipped rather than reporting a result. The test is also skipped when no schema object is visible: an account without read access sees nothing, and a pass would then say nothing about the domain.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous ACLs expose schema objects](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_permissions_schema)

<!--- Results --->

%TestResult%
