# DeviceRegSCPTool
Device Registration SCP Tool 

DeviceRegSCPTol PowerShell script is automating resolving Device Registration Service Connection Point (SCP) creation and configuration issues while configuring Hybrid Azure Active Directory Joined devices. The script verifies all needed prerequisites to install SCP, installs the missing ones, then, it creates SCP.

Also, this PowerShell fixes the common issues that may occur when creating SCP.

 

This script will save the time when troubleshooting and configuring the SCP. All you need is to run the script and enter the Global Admin (GA) credentials and it will do all stuff on behalf of you.

 

What does this PowerShell script do?

    - Checks if the server is AAD Connect server.
    - Checks if ‘ActiveDirectory’ module is installed. If not, it will install and import it.
    - Checks if Service Connection Point (SCP) is created. If not, it will request the user consent to create SCP.
    - Checks the Internet connectivity.
    - Checks if ‘MSOnline module is installed. If not, it will install and import it.
    - Checks if Service Connection Point (SCP) is configured. If it is configured, the script will show the current configuration. Otherwise, it will request the user consent to configure SCP.
    - Checks and fixes dsacls files issue.
    - Checks Global Admin credentials. If it passed, SCP will configure. Otherwise the whole operation will be aborted.
    - Creates/Configures the service Connection Point (SCP) and shows the configuration if all above succeeded. 
