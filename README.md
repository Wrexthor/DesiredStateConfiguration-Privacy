### A Desired State Configuration script to increase privacy and security in windows by disabling telemetry feaures in windows.

Made to clean up a windows install by
* Install applications using Chocolatey (commented out by default)
* Enable and configure windows firewall in addition to block outgoing traffic for commonly exploited windows applications
* Disabling telemetry functions using windows registry
* Remove unecessary windows features (smb1, ps2 etc)
* Stop/disable unecessary services (xbox, location etc)
* Remove scheduled tasks (not implemented yet)
* Set some default settings (show file extensions etc)

This is done by using Desired State Configuration(DSC)
DSC can be scheduled to check compliance, reapplying anything
that has been changed from the set baseline. 
This prevents updates from re-enabling features in the background

Use this by 
1. Downloading the repo as a zip file
2. Unpack zipfile somewhere
3. Under start menu, type ise, rightclick Windows Powershell ISE and chose run as administrator
4. Open main.ps1 (in the folder you unzipped earlier)
5. Run the script (f5)
6. Check the boxes for what modules you want, then wait for it to finish
7. Done!