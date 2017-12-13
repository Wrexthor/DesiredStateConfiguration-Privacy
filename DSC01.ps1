<#
Made to clean up a fresh windows install by
disabling telemetry functions
remove unecessary windows features (smb1, xps viewer etc)
stop/disable unecessary services (xbox, location etc)
remove scheduled tasks (mostly telemetry related stuff)
set some default settings (show file extensions etc)
This is done by using Desired State Configuration(DSC)
DSC can be scheduled to check compliance, reapplying anything
that has been changed from the set baseline. 
This prevents updates from re-enabling features in the background
#>
# DSC
Configuration BaseConfig
{
    #Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node "Localhost"
    {
        <#        
        Script DisableScheduledTasks
        {
            GetScript = {
                # array of names to disable
                $toDisable = "ProgramDataUpdater", "SmartScreenSpecific", 
                "Microsoft Compatibility Appraiser", "Consolidator", "KernelCeipTask",
                "UsbCeip", "Microsoft-Windows-DiskDiagnosticDataCollector",
                "GatherNetworkInfo", "QueueReporting"
                # store all tasks in array
                $tasks = Get-ScheduledTask
                $disableTasks = @()
                # bool for result
                $Enabled = $false
                # loop all tasks
                foreach ($task in $tasks)
                {               
                    # if the task is in the array toDisable     
                    if($toDisable -contains $task.TaskName)
                    {
                        # check if not disabled
                        if (!task.state -like "Disabled")
                        {
                            # it's not disabled, set to true
                            $disableTasks += $task
                            $Enabled = $true
                        }
                    }                    
                }
                if ($Enabled)
                {
                    return @{'State' = "Enabled"}
                }
                else 
                {
                    return @{'State' = "Disabled"}
                }                
            }
            TestScript = 
            { 
                # check if any of the tasks are enabled
                if (GetScript[state] -like "Enabled")
                {
                    # set compliant false
                    return $false
                }
                else 
                {
                    # set compliant true
                    return $true
                }
            }
            SetScript = 
            {
                $using:disableTasks
                # disable every task thats enabled and matching tasks to be disabled
                foreach ($task in $tasks)
                {
                    $task | Disable-ScheduledTask
                }
            }
        }
        #>
        # services
        Service DisableDiagTrack
        {
            Name = "DiagTrack"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableDmwappushservice
        {
            Name = "dmwappushservice"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableDiagnostichub
        {
            Name = "diagnosticshub.standardcollector.service"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableTrkWks
        {
            Name = "TrkWks"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableWMPNetworkSvc
        {
            Name = "WMPNetworkSvc"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableLocationService
        {
            Name = "lfsvc"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableMapsBroker
        {
            Name = "MapsBroker"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableXboxAuth
        {
            Name = "XblAuthManager"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableXboxSave
        {
            Name = "XblGameSave"
            StartupType = "Disabled"
            State = "Stopped"
        }
        Service DisableXboxNetApi
        {
            Name = "XboxNetApiSvc"
            StartupType = "Disabled"
            State = "Stopped"
        }
        # altering registry        
        Registry DisableWindowsConsumerFeatures
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Cloud Content"
            ValueName = "DisableWindowsConsumerFeatures"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableTelemetry
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            ValueName = "AllowTelemetry"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableAssianceClient
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0"
            ValueName = "NoActiveHelp"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableBiometrics
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics"
            ValueName = "Enabled"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableConferencing
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing"
            ValueName = "NoRDS"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableInputPersonalization
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization"
            ValueName = "AllowInputPersonalization"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableIEGeolocation
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation"
            ValueName = "PolicyDisableGeolocation"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableIERestrictions
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions"
            ValueName = "NoUpdateCheck"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableIEMain
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
            ValueName = "DoNotTrack"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableIEPrivacy
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy"
            ValueName = "EnableInPrivateBrowsing"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableIEImprovementProgram
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM"
            ValueName = "DisableCustomerImprovementProgram"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableErrorReportingDo
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
            ValueName = "DoReport"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableErrorReportingQue
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
            ValueName = "ForceQueueMode"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableErrorReportingFileTree
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
            ValueName = "DWFileTreeRoot"
            ValueType = "String"
            ValueData = ""
        }
        Registry DisableErrorReportingURL
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
            ValueName = "DWNoExternalURL"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableErrorReportingFile
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
            ValueName = "DWNoFileCollection"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableErrorReportingSecondLevel
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
            ValueName = "DWNoSecondLevelCollection"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableErrorReportingName
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
            ValueName = "DWReporteeName"
            ValueType = "String"
            ValueData = ""
        }
        Registry DisableSearchCompanion
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion"
            ValueName = "DisableContentFileUpdates"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableAdvertisingInfo
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
            ValueName = "DisabledByGroupPolicy"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableAppCombat
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            ValueName = "AITEnable"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableAppCombatInventory
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            ValueName = "DisableInventory"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableAppCombatAUR
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            ValueName = "DisableUAR"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableDeviceMetadata
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
            ValueName = "PreventDeviceMetadataFromNetwork"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableDeviceInstall
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
            ValueName = "DisableSendGenericDriverNotFoundToWER"
            ValueType = "Dword"
            ValueData = 1
        }
         Registry DisableDeviceInstallSoftware
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
            ValueName = "DisableSendRequestAdditionalSoftwareToWER"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableGameUXDownload
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
            ValueName = "DownloadGameInfo"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableGameUXUpdate
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
            ValueName = "GameUpdateOptions"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableGameUXRecent
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
            ValueName = "ListRecentlyPlayed"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableLocation
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
            ValueName = "DisableLocation"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableOneDrive
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
            ValueName = "DisableFileSyncNGSC"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableErrorReporting
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
            ValueName = "Disabled"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableErrorReportingSend
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
            ValueName = "DontSendAdditionalData"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableSearchCortana
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "AllowCortana"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableSearchLocation
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "AllowSearchToUseLocation"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableSearchPrivacy
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "ConnectedSearchPrivacy"
            ValueType = "Dword"
            ValueData = 3
        }
        Registry DisableSearchSafe
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "ConnectedSearchSafeSearch"
            ValueType = "Dword"
            ValueData = 3
        }
        Registry DisableSearchWeb
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "ConnectedSearchUseWeb"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableSearchWebMetered
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "ConnectedSearchUseWebOverMeteredConnections"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableSearchWebDisable
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName = "DisableWebSearch"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableEdge
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EdgeUI"
            ValueName = "DisableMFUTracking"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry DisableHibernation
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            ValueName = "HiberbootEnabled"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry DisableOpenThisPc
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            ValueName = "LaunchTo"
            ValueType = "Dword"
            ValueData = 1
        }
        Registry HideSearch
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\"
            ValueName = "SearchboxTaskbarMode"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry ShowFileExtensions
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            ValueName = "HideFileExt"
            ValueType = "Dword"
            ValueData = 0
        }
        Registry ShowDeliverOptimization
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
            ValueName = "DownloadMode"
            ValueType = "Dword"
            ValueData = 0
        }

    }
}
# call the function
BaseConfig