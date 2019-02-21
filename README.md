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