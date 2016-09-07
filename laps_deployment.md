## Microsoft Local Administration Password Solution Deployment

**_Introduction: How it works, what needs doin’_**

A group policy extension (referred to as a client-side extension, “CSE”) is used to get and set the computer object’s ms-Mcs-AdmPwd attribute in AD.

We will be configuring the GPO to affect the local user by name “localadmin.” This is sometimes the well-known local Administrator SID and sometimes not. I made this discovery after completing step 3 in the *Audit for local administrative users* section.

The AD schema (for computer objects) must be extended to include the necessary attributes for the group policy extension to store the values. The powershell function Update-AdmPwdADSchema adds the ms-Mcs-AdmPwd and mc-Mcs-AdmPwdExpirationTime attributes.

The group policy management templates (Admpwd.admx and en-us\AdmPwd.adml ) will be copied to the centralized policy store.

In order to easily retrieve the password from AD, MSFT provides a “fat client” and a powershell module, both installable.

In order to install the different parts of LAPS, the MSI installer can be run as follows:

```
Client participant:
msiexec /q /I LAPS.msi ADDLOCAL=CSE
Administrative console:
msiexec /q /I LAPS.msi ADDLOCAL=Management.UI,Management.PS
GPO ADMx Templates:
msiexec /q /I LAPS.msi ADDLOCAL=Management.ADMX
```

Suggested:

-   Enable “AD Recycle Bin,” which requires at least a Windows Server 2008 R2 Forest Functional Level.

**_The doin’_**

**Administrative console configuration:**

1.  download LAPS from MSFT: <https://www.microsoft.com/en-us/download/details.aspx?id=46899>

2.  if desired, designate an administrative console: the host ADMINCONSOLE

3.  On ADMINCONSOLE, run the following to perform the installation of the administrative portions of LAPS:

    ````msiexec /q /l c:\lapsmgmtinst.log /i LAPS.x64.msi ADDLOCAL=Management.UI,Management.PS````

4.  On ADMINCONSOLE, perform the installation of the ADMx files:

    ````msiexec /q /l c:\lapsadmxinst.log /i LAPS.x64.msi ADDLOCAL=Management.ADMX````

5.  Copy the following files to the respective directories the centralized policy store located at :

    -   C:\windows\policydefinitions\*AdmPwd.admx*

    -   C:\windows\policydefinitions\*en-US\AdmPwd.adml*


**Schema extension:**

1.  If desired, create a good backup of the schema master’s system state. On the schema master (as determined), run the following[1] which will be a few GB, verify “windows server backup features” feature are fully installed:

    ````wbadmin start systemstatebackup -backuptarget:e:````

2.  On ADMINCONSOLE perform the following to add the necessary attributes to objects of the computer class:

    ````
    Powershell.exe
    Import-module AdmPwd.PS
    Update-AdmPwdADSchema
    ````

3.  You can verify that the schema extension was successful by checking schema change history by running the following:

    ````
    powershell.exe
    Import-Module ActiveDirectory
    $schema = Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext)
    -SearchScope OneLevel -Filter * -Property objectClass, name, whenChanged,
    whenCreated | Select-Object objectClass, name, whenCreated, whenChanged,
    @{name="event";expression={($_.whenCreated).Date.ToShortDateString()}} |
    Sort-Object whenCreated
    $schema | Format-Table objectClass, name, whenCreated, whenChanged
    -GroupBy event -AutoSize
    ````

**Setting permissions:**

To remove Extended Rights permissions: (taken directly from LAPS_OperationsGuide 2.1.1)

1.  Open adsiedit.msc

2.  Right-click on the OU that contains the computer accounts that you are installing LAPS on and select Properties.

3.  Click the Security tab.

4.  Click Advanced.

5.  Select the Group(s) or User(s) that you don’t want to be able to read the password and then click Edit.

6.  Uncheck *All extended rights*.


** To verify Extended Rights have been removed:**

1.  On the administrative console, run:

    ````
    powershell.exe
    Import-module AdmPwd.PS
    Find-AdmPwdExtendedrights –identity “dc=contoso,dc=corp” | out-gridview
    ````
    There shouldn’t be any “ExtendedRightHolders” that you do not wish on OUs or objects that you wish.

**To add write permission to the SELF ACE to the needed computer class objects’ attributes:**

1.  On the administrative console, run:

    ````
    powershell.exe
    Import-module AdmPwd.PS
    Set-AdmPwdComputerSelfPermission -OrgUnit “dc=contoso,dc=corp”
    ````

    The approach to allow any computer object to make the intended changes is not a security risk. Otherwise, you could be granular with which OUs.

2.  To verify, use adsiedit.msc to take a look at the effective permissions on the security tab, of the domain-wide SELF built-in ACE on a computer object below the targeted OU. Look for the following permissions:

    -   Read ms-Mcs-AdmPwd: unchecked

    -   Write ms-Mcs-AdmPwd: checked

    -   Read ms-Mcs-AdmPwdExpirationTime: checked

    -   Write ms-Mcs-AdmPwdExpirationTime: checked


**To add specific users the ability to read the stored passwords:**

1.  Create a security group *LAPS_Allowed_Read*.

2.  On the administrative console, run:

    ````
    powershell.exe
    Import-module AdmPwd.PS
    Set-AdmPwdReadPasswordPermission -OrgUnit “dc=contoso,dc=corp”-AllowedPrincipals LAPS_Allowed_Read
    ````

3.  To verify, use adsiedit.msc to take a look at the effective permissions on the security tab, of the contoso\LAPS_Allowed_Read ACE on a computer object below the targeted OU. Look for the following permissions:

    -   Read ms-Mcs-AdmPwd: checked

    -   Write ms-Mcs-AdmPwd: unchecked

    -   Read ms-Mcs-AdmPwdExpirationTime: checked

    -   Write ms-Mcs-AdmPwdExpirationTime: unchecked


**To add specific users the ability to force a reset via the LAPS Group Policy client-side extension for the stored passwords[2]:**

1.  Create a security group *LAPS_Allowed_Reset*.

2.  On the administrative console, run:

    ````
    powershell.exe
    Import-module AdmPwd.PS
    Set-AdmPwdResetPasswordPermission –OrgUnit “dc=contoso,dc=corp”-AllowedPrincipals LAPS_Allowed_Reset
    ````

3.  To verify, use adsiedit.msc to take a look at the effective permissions on the security tab, of the contoso\LAPS_Allowed_Reset ACE on a computer object below the targeted OU. Look for the following permissions:

    -   Read ms-Mcs-AdmPwd: unchecked
    -   Write ms-Mcs-AdmPwd: unchecked
    -   Read ms-Mcs-AdmPwdExpirationTime: checked
    -   Write ms-Mcs-AdmPwdExpirationTime: checked


**Audit for local administrative users:**

With LAPS, you have the option to either change the password for the account with the well-known SID[3] of the local administrator, or by a username you’ve provided. The reports produced below allowed me to make the conclusion that I have too many objects that aren’t using the default Administrator account (the admin account is not the well-known SID). So, in the GPO, I chose to populate the “Name of administrator account to manage” option.

To produce a list of computers that the scripts will use as input, where each line contains a LAPS target computer name, perform the following:

1.  Produce a list of computers by using dsa.msc “Saved Queries” feature near the top of the tree, exporting to a CSV, then opening in Excel. Copy the all the computer names into a text file (remove non-target computers). The LDAP query should be:

    ````
    (&(objectCategory=Computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
    ````

    Otherwise, you can produce the list with:

    ````get-adcomputer -searchbase "dc=contoso,dc=corp" -filter {(enabled -eq "true")} | select name –expandproperty name````

2.  To verify that you don’t have any local admin accounts you don’t know about, run the following in powershell (I’m not proud of it, but it does the job):

    ````
    foreach ($computername in (get-content "\\deployserver\LAPS\targetlist.txt") ) {
    ((get-wmiobject Win32_GroupUser -computer $computername | `
    where { `
    ( $_.GroupComponent -like '*Administrators*' ) `
    -and `
    ( $_.GroupComponent -notlike '*$((get-wmiobject win32_computersystem).domain.split('.')[0])*' ) `
    -and `
    ( $_.PartComponent -like '*Win32_UserAccount*') `
    -and `
    (
        ( $_.PartComponent -like "*Domain=""$computername""*") `
        -or `
        ( $_.PartComponent -notlike "*Domain=""$((get-wmiobject win32_computersystem).domain.split('.')[0])""*") `
        ) `
    } `
    ).partcomponent) | foreach { ($_).split('"')[1,3] ; "!!"} 2>&1 >> c:\localadminlist.out
    }
    ````

    You can review the file c:\localadminlist.out for any computer that has any administrator other than localadmin, then make the corrections as necessary: remove any administrator that isn’t \`localadmin\` and/or rename \`Administrator\` to \`localadmin\`.

3.  To verify that the admin account you know about is the well-known SID Administrator, run the following in powershell (note this uses powershell remoting, setting it up is covered in “Configure powershell remote” below) :

    ````
    $var = foreach ($targetcomputer in (get-content "\\deployserver\LAPS\targetlist.txt") ) {
    write-output "connecting to:, $targetcomputer"
    Invoke-command -scriptblock {
    function get-usersid{
        param(
        [string]$domain,
        [string]$user
        )
        $objUser = New-Object System.Security.Principal.NTAccount("$domain", "$user")
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $strSID.Value
    }
    if ($(get-usersid -domain $env:computername -user localadmin) -match 'S-1-5-21-..........-..........-..........-500') {
        write-output “$env:computername,localadmin user is the well-known SID Administrator”
    }
    else {
        write-output “$env:computername,localadmin user is not the well-known SID Administrator”
    }
    } -computername $targetcomputer
    }
    $var | out-file c:\localadminsidlist.csv
    ````

    You can review c:\localadminsidlist.csv to review status and make corrections. Remember the F4 “apply last selected style” hotkey in Excel is your friend. You might take advantage of this by disabling computer objects that are stale… etc.

**Client deployment:**

Several guides state to deploy the LAPS GP CSE via group policy; I hate that method as it’s synchronous during boot and can be declarative in OU scope. Instead, I prefer to semi-manually manage the deployment process by utilizing powershell remoting and executing silent installs by hand.

1.  Configure powershell remote[4]:

-   Computer Configuration\Administrative Templates\Windows Components\Windows Powershell\ *Turn on Script Execution*: Enabled, Execution Policy: Allow all scripts

-   Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\ *Trusted Hosts*: Enabled, *TrustedHostsLists*: \[a subnet wildcard, like 10.10.1.*\]

-   Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Services\ *Allow remote server management through WinRM*: Enabled, *IPv4 filter*: \[subnet range\]

2.  CredSSP is not necessary for the benefit; without it enabled, you can’t access a network resource from a powershell remoting session (\`Enter-PSSession\` or \`Invoke-Command\`). Instead, we must copy down the MSI then execute it locally on the system via the powershell remoting session (\`Enter-PSSession\` or \`Invoke-Command\`):

For 64-bit hosts:
    ````
    foreach ($targetcomputer in (get-content "\\deployserver\LAPS\targetlist.txt") ) {
    copy "\\deployserver\LAPS\LAPS.x64.msi" \\$targetcomputer\c$
    Invoke-Command -scriptblock {
    hostname
    cmd.exe /c c:\Windows\system32\msiexec.exe /norestart /i "c:\LAPS.x64.msi" /l c:\lapsinst.log /qn ADDLOCAL=CSE
    } -computername $targetcomputer
    }
    ````

For 32-bit hosts:
    ````
    $targetcomputer = "[target host here]"
    copy "\\deployserver\LAPS\LAPS.x86.msi" \\$targetcomputer\c$
    Invoke-Command -scriptblock {
    cmd.exe /c c:\Windows\system32\msiexec.exe /norestart /i "c:\LAPS.x86.msi"" /l c:\lapsinst.log /qn ADDLOCAL=CSE
    } -computername $targetcomputer
    ````

3.  Verify installation by checking a few things are where they should be:

    ````
    foreach ($targetcomputer in (get-content "\\deployserver\LAPS\targetlist.txt") ) {
    Invoke-Command -scriptblock {
    if ( @(get-EventLog -logname "Application" -after (get-date).addminutes(-120) -message "*Local Administrator Password     Solution*completed successfully.*").length -eq 1) {
        write-output $("LAPS has installed correctly on, $env:COMPUTERNAME.")
    }
    else {
        write-error $("LAPS install failed on, $env:COMPUTERNAME")
    }
    } -computername $targetcomputer
    }
    ````

**Group Policy Configuration:**

Since we placed the ADMX and ADML files into the central policy store previously (within the section “Administrative console configuration”), the administrative template for LAPS should be available on any gpmc.msc client.

1.  Scoping the application of the GPO for control of the LAPS client should be at the level you wish to target. Keep in mind with no LAPS client, the LAPS configuration will not have anything to configure… no harm, no foul. For this reason, we can actually apply the GPO that controls the LAPS configuration at the root of the domain (at the dc=contoso,dc=corp container) and enable *Enforce* to affect all computer objects.

2.  Gpmc.msc

    -   Computer configuration\Policies\Administrative Templates\LAPS

        -   Enable local admin password management: Enabled

        -   Name of administrator account to manage: Enabled, localadmin (see the *Audit for local administrative users* section above for more info)

        -   Do not allow password expiration time longer than required by policy: Enabled

        -   Password Settings: leave as default, if acceptable.

**Verify configuration/testing:**

1.  Choose a target client: TESTWORKSTATION

2.  Perform the installation as noted in the *Client deployment* section above.

3.  Update group policy on the client.

    ````gpupdate /force````

4.  Verify the configuration is present by checking the registry:

    ````reg query “HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd”````

5.  Continue to the *Access the LAPS controlled local administrative password* section below.

**Access the LAPS controlled local administrative password:**

1.  Logon to a workstation as someone who is a member of the group *LAPS_Allowed_Read* assigned in the “To add specific users the ability to read the stored passwords” step in the *Setting permissions* section above.

2.  This step covers several ways to access the LAPS set local administrator password. You can choose your favorite method, using adsiedit.msc, dsa.msc with advanced features enabled \[note that oddly you must navigate to the object in the tree in order to reveal the Attribute Editor tab versus using the “Find Computers” window\], powershell on an administrative console, or the fat client on an administrative console:

    ** If the attribute listed in each step below isn’t accessible or appears as “&lt;Not set&gt;”, then re-verify that: you’re running whatever tool is accessing the AD LDAP with a user who is part of the LAPS_Allowed_Read group, then verify you’ve applied the permissions correctly as stated in the “To add specific users the ability to read the stored passwords” step in the *Setting permissions* section above.

    -   Using Adsiedit.msc:

        1.  Navigate the tree until you arrive on the CN=\[workstation\], right-click&gt; Properties.

        2.  On the Attribute Editor tab of the object properties, navigate to the ms-Mcs- AdmPwd attribute. It should be readable.

    -   Using dsa.msc:

        1.  Go to View&gt; check Advanced Features

        2.  Navigate the tree until you arrive on the \[workstation\] computer object, right-click properties.

        3.  On the Attribute Editor tab of the object properties, navigate to the ms-Mcs- AdmPwd attribute. It should be readable.

    -   Using powershell on an administrative console as configured following the *Administrative console configuration* section above:

        1.  Start powershell

        2.  Run the following:

            ````
            import-module AdmPwd.PS
            Get-AdmPwdPassword –ComputerName [workstation]
            ````

    -   Using the Fat client as configured following the *Administrative console configuration* section above:

        1.  Run C:\Program Files\LAPS\AdmPwd.UI.exe

        2.  Enter the \[workstation\] in to the ComputerName field, hit enter, or click Search.

3.  Logon as the administrative user to the workstation using the password.

**Verify that a user that’s not in *LAPS_Allowed_Read* can’t see the local password:**

1.  Log onto a system that has one of the tools covered in the previous section *Manage/access the Local administrative password* installed.

2.  Attempt to go through the procedure as noted in the Manage/access the Local administrative password section.

3.  You should see &lt;Not set&gt; as the ms-Mcs-AdmPwd attribute. If you see the password, then the user still has the right Extended Rights on the object. Follow the “To remove Extended Rights permissions” step in the *Setting permissions* section above.

**Verify that the LAPS controlled local administrative password can be reset using the LAPS tools:**

1.  Trigger the LAPS client to perform a reset of a workstation account by expiring the current password using the powershell client or the Fat client UI, running the following as a user who is in the *LAPS_Allowed_Reset* group:

    -   Using powershell on an administrative console as configured following the *Administrative console configuration* section above:

        1.  Start powershell.
        2.  Run the following:
            ````
            import-module AdmPwd.PS
            Get-AdmPwdPassword –ComputerName [workstation]
            Reset-AdmPwdPassword -ComputerName [workstation] -WhenEffective $(get-date)
            ````
        3.  Perform a group policy update on the target workstation.

    -   Using the Fat client as configured following the *Administrative console configuration* section above:

        1.  Run C:\Program Files\LAPS\AdmPwd.UI.exe
        2.  Enter the \[workstation\] in to the ComputerName field, hit enter, or click Search.
        3.  Click Set.
        4.  Perform a group policy update on the target workstation.

**Enable auditing of access to the ms-Mcs-AdmPwd attribute:**

Using powershell on an administrative console as configured following the *Administrative console configuration* section above

1.  Start powershell.

2.  Run the following:

    ````
    import-module AdmPwd.PS
    Set-AdmPwdAuditing –OrgUnit:dc=contoso,dc=corp –AuditedPrincipals Everyone
    ````

3.  The Security events will be logged as event ID 4662 with detail reference containing the DN of the accessed object and the operation property: {b04b21db-0992-4551-a813-4d8e2a27ff1e}


**Troubleshooting:**

Troubleshooting is covered in detail in the Troubleshooting section of the LAPS_OperationsGuide.docx document.

Quickly, LAPS will file away events into the Application Event Log. You can adjust the verbosity level of the event messages by changing the REG_DWORD:

    ````HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}: ExtensionDebugLevel````

The values can be {0x0, 0x1, or 0x2} == {errors only, errors and warnings, log everything}.

[1] If you need to perform a restore of AD (inclusive of the schema and permissions), you will have to perform the procedure detailed in the “restore from backup media for authoritative restore” section on <http://technet.microsoft.com/en-us/library/bb727062.aspx#E0KB0AA>

[2] Basically, these users can set the attribute that tells the CSE that the password is expired which will cause LAPS (via the CSE) to do its thing and reset the password.

[3] https://support.microsoft.com/en-us/kb/243330?wa=wsignin1.0

[4] http://www.briantist.com/how-to/powershell-remoting-group-policy/
