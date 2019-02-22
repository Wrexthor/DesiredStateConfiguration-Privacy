Configuration InitialScript
{
    # this script installs the modules needed for the rest of the DSC configurations to work    
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
        Script InstallModules
        {
            GetScript = {}
            TestScript = {}
            SetScript = 
            {
                $modules = ('PSDscResources','cChoco', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'ComputerManagementDsc', 'WindowsDefender', 'DSCR_AppxPackage', 'NetworkingDsc')
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

# install required packages for the rest of configuration
InitialScript