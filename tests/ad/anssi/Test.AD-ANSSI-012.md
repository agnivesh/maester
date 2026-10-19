This test checks that the Active Directory consoles are not set up to run programs stored on ordinary file servers.

Display specifiers are forest-wide objects that tell the Active Directory consoles what to show, including extra entries in the right-click menu of users, groups and other objects. Such an entry can start any program or script, by path. When that path points to a share on an ordinary file server, whoever can write to that share can replace the script, and it then runs with the rights of the administrator who clicks the menu entry. That turns a file server, usually much less protected than the domain controllers, into a way to take over administrator accounts.

#### What ANSSI says and how it rates the risk

ANSSI explains that display specifiers are an extension mechanism for the dsa.msc menus that can run COM objects or scripts, and that scripts referenced from file servers outside SYSVOL should be removed or moved to the SYSVOL share of a domain controller.

ANSSI rates it level 1. Maester rates it High: the script runs only when an administrator opens the menu, and the attacker must first be able to change the script or the specifier.

#### Remediation action

For each entry listed in the results with the location "File server", remove it from the display specifier if it is no longer used. If it is still needed, move the program to the SYSVOL share of the domain, which by default only administrators can change, and update the entry. Then check who can write to the old share and to the program, in case it was already tampered with.

Entries that point to SYSVOL or NETLOGON do not fail the test, but each should still be needed: remove the ones that are not.

#### How the test works

The test reads every display specifier of the forest, in every language container, from the Configuration partition, and looks at their `adminContextMenu` and `shellContextMenu` values. A static entry has the form `<order>,<menu text>,<command>`. The test fails for each entry whose command starts with a network path (`\\server\share\...`) on a share other than SYSVOL or NETLOGON. Entries on SYSVOL or NETLOGON are listed but do not fail. The results show the display specifier with its language code, the attribute, the program and its location.

Some things are not checked:

- entries that load a COM component (`<order>,{class ID}`): the component is installed on each administrator's computer, not stored in the directory;
- programs on a local drive or at a web address;
- who can actually write to the shares.

If the display specifiers cannot be read, or none is found, the test is skipped rather than passing.

Each row of the result table starts with the domain that holds the object, read from its distinguished name. A row without one shows the domain that was scanned.

#### Related links

- [ANSSI Active Directory checkpoints: Dangerous Display Specifiers](https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#vuln_display_specifier)
- [Microsoft Learn: Display specifiers](https://learn.microsoft.com/windows/win32/ad/display-specifiers)
- [Microsoft Learn: Registering a static context menu item](https://learn.microsoft.com/windows/win32/ad/registering-a-static-context-menu-item)

<!--- Results --->

%TestResult%
