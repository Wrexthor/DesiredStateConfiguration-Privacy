<#
.SYNOPSIS
   Script to configure and apply DSC templates
.DESCRIPTION
   GUI prompting user to chose what DSC templates to apply
   installs required modules for DSC templates, runs DSC configurations
   and installs the .mof files in addition to setting a DSC meta configuration
   that automatically applies configuration every 30 minutes if configuration drift has occured
.NOTES
   Author: Wrexthor
   Github: https://github.com/Wrexthor/DesiredStateConfiguration-Privacy
#>

function Use-RunAs 
    {    
        # Check if script is running as Adminstrator and if not use RunAs 
        # Use Check Switch to check if admin          
        param([Switch]$Check) 
         
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent() 
            ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
             
        if ($Check) { return $IsAdmin }     
     
        if ($MyInvocation.ScriptName -ne "") 
        {  
            if (-not $IsAdmin)  
            {  
                try 
                {  
                    $arg = "-file `"$($MyInvocation.ScriptName)`"" 
                    Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'  
                } 
                catch 
                { 
                    Write-Warning "Error - Failed to restart script with runas"  
                    break               
                } 
                exit # Quit this session of powershell 
            }  
        }  
        else  
        {  
            Write-Warning "Error - Script must be saved as a .ps1 file first"  
            break  
        }  
    }
# make sure script is running as admin
use-runas

# This form was created using POSHGUI.com  a free online gui designer for PowerShell

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Configuration                   = New-Object system.Windows.Forms.Form
$Configuration.ClientSize        = '160,152'
$Configuration.text              = "Configuration"
$Configuration.TopMost           = $false

$DisableTelemetry                = New-Object system.Windows.Forms.CheckBox
$DisableTelemetry.text           = "DisableTelemetry"
$DisableTelemetry.AutoSize       = $true
$DisableTelemetry.width          = 40
$DisableTelemetry.height         = 20
$DisableTelemetry.location       = New-Object System.Drawing.Point(7,10)
$DisableTelemetry.Font           = 'Microsoft Sans Serif,10'

$AddSecurity                     = New-Object system.Windows.Forms.CheckBox
$AddSecurity.text                = "AddSecurity"
$AddSecurity.AutoSize            = $true
$AddSecurity.width               = 40
$AddSecurity.height              = 20
$AddSecurity.location            = New-Object System.Drawing.Point(7,30)
$AddSecurity.Font                = 'Microsoft Sans Serif,10'

$SetDefaults                     = New-Object system.Windows.Forms.CheckBox
$SetDefaults.text                = "SetDefaults"
$SetDefaults.AutoSize            = $true
$SetDefaults.width               = 40
$SetDefaults.height              = 20
$SetDefaults.location            = New-Object System.Drawing.Point(7,51)
$SetDefaults.Font                = 'Microsoft Sans Serif,10'

$InstallApps                     = New-Object system.Windows.Forms.CheckBox
$InstallApps.text                = "InstallApps"
$InstallApps.AutoSize            = $true
$InstallApps.width               = 40
$InstallApps.height              = 20
$InstallApps.location            = New-Object System.Drawing.Point(7,71)
$InstallApps.Font                = 'Microsoft Sans Serif,10'

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Continue"
$Button1.width                   = 84
$Button1.height                  = 26
$Button1.location                = New-Object System.Drawing.Point(22,105)
$Button1.Font                    = 'Microsoft Sans Serif,10'

$Configuration.controls.AddRange(@($DisableTelemetry,$AddSecurity,$SetDefaults,$InstallApps,$Button1))

# used to specify which modules to install and which files to run
function doStuff()
{
    # list of all modules
    #$modules = ('PSDscResources','cChoco', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'ComputerManagementDsc', 'WindowsDefender', 'DSCR_AppxPackage', 'NetworkingDsc')

    # create arrays
    $modules = @('PSDscResources')
    $items = @('meta_config.ps1')
    # create object to return
    $obj = "" | Select-Object -Property modules,items
    if ($DisableTelemetry.Checked)
    {
        #$modules += 
        $items += 'disable_telemetry.ps1'
    }
    if ($AddSecurity.Checked)
    {
        $modules += 'NetworkingDsc', 'WindowsDefender'
        $items += 'add_security.ps1'
    }
    if ($InstallApps.Checked)
    {
        $modules += 'cChoco'
        $items += 'install_apps.ps1'
    }
    if ($SetDefaults.Checked)
    {        
        #$modules +=
        $items += 'set_default_settings.ps1'
    }
    # add arrays to object    
    $obj.modules = $modules    
    $obj.items = $items    
    # return object
    return $obj
}

# event listener for button click
$Button1.Add_Click(
{        
    $script:obj = doStuff    
    $Configuration.close()
})

# show GUI
$Configuration.ShowDialog()

write-host "Installing modules.." -ForegroundColor Yellow

# set psgallery to trusted to prevent popups
Set-PSRepository psgallery -InstallationPolicy trusted
# install modules
foreach ($module in $obj.modules) 
{        
    install-Module -Name $module -SkipPublisherCheck
}
# set location to path of this script
cd $PSScriptRoot
write-host "Running configurations.." -ForegroundColor Yellow
# run configurations
foreach ($item in $obj.items)
{
    & ".\$item"
}
# apply meta configuration
Set-DscLocalConfigurationManager -path (Get-ChildItem -Recurse -filter "*meta.mof").DirectoryName

# get all .mof files except meta file
$files = Get-ChildItem -Recurse -filter "*.mof" -Exclude "*meta.mof"

# apply found files
foreach($file in $files)
{
    Start-DscConfiguration -path $file.DirectoryName -force -JobName 'DSC'
}

# wait for jobs to finish
get-job -Name 'DSC' | wait-job

write-host "Configurations applied, have fun!" -ForegroundColor Green
start-sleep -Seconds 5

# if for some reason you want to remove the DSC configurations, uncomment below and run only that line
#Remove-DscConfigurationDocument -Stage Current, Pending, Previous -Verbose