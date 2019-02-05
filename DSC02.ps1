<#
Made to clean up a fresh windows install by
disabling telemetry functions
remove unecessary windows features (smb1, ps2 etc)
stop/disable unecessary services (xbox, location etc)
remove scheduled tasks (mostly telemetry related stuff)
set some default settings (show file extensions etc)
This is done by using Desired State Configuration(DSC)
DSC can be scheduled to check compliance, reapplying anything
that has been changed from the set baseline. 
This prevents updates from re-enabling features in the background
#>
Configuration InitialScript
{
    # this script installs the modules needed for the rest of the DSC files to work
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
        Script InstallModules
        {
            GetScript = {}
            TestScript = {}
            SetScript = 
            {
                $modules = ('PSDscResources','cChoco', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'ComputerManagementDsc', 'WindowsDefender', 'DSCR_AppxPackage')
                function Install-RequiredModules ($modules)
                {    
                    update-module -Verbose
                    foreach ($module in $modules) 
                    {
                        install-Module -Name $module -SkipPublisherCheck -Verbose
                    } 
                }
                Install-RequiredModules $modules
            }            
        }
    }

}
Configuration InstallApplications
# installs applications using Chocolatey
# anything in Chocolatey repos can be added
{
    Import-DscResource -ModuleName cChoco
    Node $env:COMPUTERNAME
    {
        cChocoinstaller Install 
        {
            InstallDir = "C:\Choco"
        }
        cChocoPackageInstaller Install7Zip 
        {
            Name = '7Zip'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller InstallNotepadplusplus
        {
            Name = 'notepadplusplus'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller InstallsplunkUniversalforwarder
        {
            Name = 'splunk-universalforwarder'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installorigin
        {
            Name = 'origin'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installteamviewer 
        {
            Name = 'teamviewer'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installccleaner
        {
            Name = 'ccleaner'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installopenssh
        {
            Name = 'openssh'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installtreesizefree
        {
            Name = 'treesizefree'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installsysinternals
        {
            Name = 'sysinternals'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installgit
        {
            Name = 'git'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installfirefox
        {
            Name = 'firefox'
            DependsOn = '[cChocoInstaller]Install'
        }
        cChocoPackageInstaller Installduplicati
        {
            Name = 'duplicati'
            DependsOn = '[cChocoInstaller]Install'
        }
    }
}
<#
Configuration DisableScheduledTasks
{
    #Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
               
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
        
    }
}
#>

Configuration DisableServices
{
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
        # services
     Service DisableDiagTrack
     # http://batcmd.com/windows/10/services/diagtrack/
     {
         Name = "DiagTrack"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableDmwappushservice
     # http://batcmd.com/windows/10/services/dmwappushservice/
     # NOTE Sysprep w/ Generalize WILL FAIL if you disable the DmwApPushService
     {
         Name = "dmwappushservice"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableDiagnostichub
     # http://batcmd.com/windows/10/services/diagnosticshub-standardcollector-service/
     {
         Name = "diagnosticshub.standardcollector.service"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableTrkWks
     # http://batcmd.com/windows/10/services/trkwks/
     {
         Name = "TrkWks"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableWMPNetworkSvc
     # http://batcmd.com/windows/10/services/wmpnetworksvc/
     {
         Name = "WMPNetworkSvc"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableLocationService
     # http://batcmd.com/windows/10/services/lfsvc/
     {
         Name = "lfsvc"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableMapsBroker
     # http://batcmd.com/windows/10/services/mapsbroker/
     {
         Name = "MapsBroker"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service DisableXboxAuth
     # below are 5 xbox services, comment out if xbox features are needed
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
     Service DisableXboxGipSvc
     {
         Name = "XboxGipSvc"
         StartupType = "Disabled"
         State = "Stopped"
     }
     Service Disablexbgm
     {
         Name = "xbgm"
         StartupType = "Disabled"
         State = "Stopped"
     }   
    }
      
}
Configuration AlterRegistry
{
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
     # altering registry        
     Registry DisableWindowsConsumerFeatures
     # removes apps like candy crush, twitter etc from installing
     # https://blogs.technet.microsoft.com/mniehaus/2015/11/23/seeing-extra-apps-turn-them-off/
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Cloud Content"
         ValueName = "DisableWindowsConsumerFeatures"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableTelemetry
     # disabled win10 home/pro telemetry
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
     <#
     Registry DisableBiometrics
     # this disables biometrics, uncommented by default to avoid breaking functionality
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics"
         ValueName = "Enabled"
         ValueType = "Dword"
         ValueData = 0
     }
     #>
     <#     
     # commented out due to not knowing exactly what it impacts
     Registry DisableConferencing
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing"
         ValueName = "NoRDS"
         ValueType = "Dword"
         ValueData = 1
     }
     #>
     <#
     Registry DisableInputPersonalization
     # disables input personalization
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization"
         ValueName = "AllowInputPersonalization"
         ValueType = "Dword"
         ValueData = 0
     }     
     Registry DisableIEGeolocation
     # disable geolocation in IE
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
     Registry EnableDoNotTrack
     # enables do not track in IE
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
         ValueName = "DoNotTrack"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableIEPrivacy
     # enables private browsing mode
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy"
         ValueName = "EnableInPrivateBrowsing"
         ValueType = "Dword"
         ValueData = 0
     }
     #>
     Registry DisableIEImprovementProgram
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM"
         ValueName = "DisableCustomerImprovementProgram"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableErrorReportingDo
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
         ValueName = "DoReport"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableErrorReportingQue
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
         ValueName = "ForceQueueMode"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableErrorReportingFileTree
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
         ValueName = "DWFileTreeRoot"
         ValueType = "String"
         ValueData = ""
     }
     Registry DisableErrorReportingURL
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
         ValueName = "DWNoExternalURL"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableErrorReportingFile
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
         ValueName = "DWNoFileCollection"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry SetErrorReportingSecondLevel
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
         ValueName = "DWNoSecondLevelCollection"
         ValueType = "Dword"
         ValueData = 1
     }
     <#
     # commented out as it could affect other things badly
     Registry DisableErrorReportingName
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
         ValueName = "DWReporteeName"
         ValueType = "String"
         ValueData = ""
     }
     #>
     <#
     Registry DisableSearchCompanion
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion"
         ValueName = "DisableContentFileUpdates"
         ValueType = "Dword"
         ValueData = 1
     }
     #>
     Registry DisableAdvertisingInfo
     # Disable app access to user advertising information
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
         ValueName = "DisabledByGroupPolicy"
         ValueType = "Dword"
         ValueData = 1
     }
     <#
     Registry DisableAppCombat
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
         ValueName = "AITEnable"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableAppCombatInventory
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
         ValueName = "DisableInventory"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableAppCombatAUR
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
         ValueName = "DisableUAR"
         ValueType = "Dword"
         ValueData = 1
     }
     
     Registry DisableDeviceMetadata
     # Disable device metadata retrieval from the Internet
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
         ValueName = "PreventDeviceMetadataFromNetwork"
         ValueType = "Dword"
         ValueData = 1
     }
     
     Registry DisableDeviceInstall
     # disables sending data to microsoft about failed driver installs
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
         ValueName = "DisableSendGenericDriverNotFoundToWER"
         ValueType = "Dword"
         ValueData = 1
     }
      Registry DisableDeviceInstallSoftware
      # disables sending data to microsoft about failed software installs
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
         ValueName = "DisableSendRequestAdditionalSoftwareToWER"
         ValueType = "Dword"
         ValueData = 1
     }
     
     Registry DisableGameUXDownload
     # Disable game information and options retrieval from the Internet
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
         ValueName = "DownloadGameInfo"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableGameUXUpdate
     # Disable game information and options retrieval from the Internet
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
         ValueName = "GameUpdateOptions"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableGameUXRecent
     # Prevents recently played games being collected
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameUX"
         ValueName = "ListRecentlyPlayed"
         ValueType = "Dword"
         ValueData = 0
     }
     #>
     Registry DisableLocation
     # Disable location and sensors
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
         ValueName = "DisableLocation"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableOneDrive
     # Disable OneDrive for file storage
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
         ValueName = "DisableFileSyncNGSC"
         ValueType = "Dword"
         ValueData = 1
     }
     <#
     Registry DisableErrorReporting
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
         ValueName = "Disabled"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableErrorReportingSend
     # disables sending data to microsoft
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
         ValueName = "DontSendAdditionalData"
         ValueType = "Dword"
         ValueData = 1
     }
     #>
     Registry DisableSearchCortana
     # Disable Cortana
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
         ValueName = "AllowCortana"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableSearchLocation
     # Disable Cortana
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
         ValueName = "AllowSearchToUseLocation"
         ValueType = "Dword"
         ValueData = 0
     }
     <#
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
     #>
     Registry SetSearchWebDisable
     # disable searching the web when searching
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
         ValueName = "DisableWebSearch"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableMFUTracking
     # Prevent data collection in Edge
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EdgeUI"
         ValueName = "DisableMFUTracking"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry DisableHibernation
     # disable hibernation
     # comment out if hibernation is something you want
     # also be aware that on laptops hibernation is prefered rather than sleep since
     # hibernation files are protected by bitlocker (if enabled)
     # while sleep keeps everything in RAM which can be a security issue if device is stolen
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
         ValueName = "HiberbootEnabled"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry LaunchToThisPc
     # when opening explorer it launches to this pc instead of quick access items
     # this is the old behaviour of windows
     # https://www.itechtics.com/configure-windows-10-file-explorer-open-pc-instead-quick-access/
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
         ValueName = "LaunchTo"
         ValueType = "Dword"
         ValueData = 1
     }
     Registry HideSearch
     # hides the search bar from taskbar
     # comment out if you want to keep the search bar
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\"
         ValueName = "SearchboxTaskbarMode"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry ShowFileExtensions
     # show file extenstions in Explorer
     # comment out if you don't want file extensions
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
         ValueName = "HideFileExt"
         ValueType = "Dword"
         ValueData = 0
     }
     Registry DisableDeliverOptimization
     # disables delivery optimization, downloading/uploading updates from other pc's on internet/lan
     {
         Ensure = "Present"
         Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
         ValueName = "DownloadMode"
         ValueType = "Dword"
         ValueData = 0
     }
    }     
}

<#
Configuration UninstallStoreApps
{
    Import-DscResource –ModuleName 'cAppxPackage'
    Node $env:COMPUTERNAME
    {
        script cAppxPackage
        {
        }
    }
}
#>

Configuration RemoveFeatures
# removes unsecure features not used by modern OS'es
{
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
        WindowsOptionalFeature removePS2
        {
            Name = 'MicrosoftWindowsPowerShellV2'
            Ensure = 'Disable'
            RemoveFilesOnDisable = $true
        }
        WindowsOptionalFeature removePS2Root
        {
            Name = 'MicrosoftWindowsPowerShellV2Root'
            Ensure = 'Disable'
            RemoveFilesOnDisable = $true
        }
        WindowsOptionalFeature removeSmb1Client
        {
            Name = 'SMB1Protocol-Client'
            Ensure = 'Disable'
            RemoveFilesOnDisable = $true
        }
        WindowsOptionalFeature removeSmb1Server
        {
            Name = 'SMB1Protocol-Server'
            Ensure = 'Disable'
            RemoveFilesOnDisable = $true
        }
    }
}

# call functions
InstallApplications
DisableServices
AlterRegistry
InitialScript
RemoveFeatures