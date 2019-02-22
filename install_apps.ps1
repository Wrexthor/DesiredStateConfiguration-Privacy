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
        <#
        Disabled due to privacy concerns, CCleaner sends data all over the place
        cChocoPackageInstaller Installccleaner
        {
            Name = 'ccleaner'
            DependsOn = '[cChocoInstaller]Install'
        }
        #>
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

InstallApplications