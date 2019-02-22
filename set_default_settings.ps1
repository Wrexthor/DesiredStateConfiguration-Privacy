Configuration SetDefaultSettings
{
    # sets some default settings in windows
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
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

# sets some deafault settings in windows
SetDefaultSettings