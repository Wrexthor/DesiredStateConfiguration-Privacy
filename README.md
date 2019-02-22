### A Desired State Configuration script to increase privacy and security in windows by disabling telemetry feaures in windows.

Made to clean up a windows install by
* Install applications using Chocolatey (make sure to change the install_apps.ps1 file to only install apps you want)
* Enable and configure windows firewall in addition to block outgoing traffic for commonly exploited windows applications (in add_security)
* Disabling telemetry functions using windows registry (in disable_telemetry)
* Remove unecessary windows features, smb1, ps2 (in add_security)
* Stop/disable unecessary services, xbox, location etc (in disable_telemetry)
* Remove scheduled tasks (not implemented yet, will be in disable_telemetry)
* Set some default settings, show file extensions etc (in default_settings)

This is done by using Desired State Configuration(DSC)s
DSC can be scheduled to check compliance (set to every 30min in meta_config.ps1)
and reapplying anything that has been changed from the desired state.
This reapplies all the settings in case Microsoft decides to revert them with an update

Use this by 
1. Downloading the repo as a zip file
2. Unpack zipfile somewhere
3. Rightclick main.ps1 (in the folder you unzipped to) and click run with PowerShell
4. Check the boxes for what modules you want, click continue then wait for it to finish
5. Done!

To remove the DSC configurations from being reapplied, run the last command in the script or the following in powershell
Remove-DscConfigurationDocument -Stage Current, Pending, Previous -Verbose