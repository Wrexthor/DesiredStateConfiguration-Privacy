configuration roles {
    param (
        [Parameter(Mandatory=$true)][pscredential]$LocalUserPassword
    )
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Node $env:COMPUTERNAME
    {
        WindowsFeature installWindowsPowerShellWebAccess
        {
            Ensure = "Present"
            Name = "WindowsPowerShellWebAccess"
            IncludeAllSubFeature = $true
        }
        Script InstallPSWA
        {
            GetScript = {}
            TestScript = 
            {
                # check if pool already exist and is compliant
                if(Get-IISAppPool "pswa_pool")
                {return $true}
                else                
                {return $false}
            }
            SetScript = 
            {
                Install-PswaWebApplication -UseTestCertificate
            }
            # requires feature to be installed
            DependsOn = WindowsPowerShellWebAccess
        }
        Script newUser
        {
            GetScript = {}
            TestScript = {Get-LocalUser -Name "boss"}
            SetScript = {New-LocalUser -name "boss" -password $LocalUserPassword}
        }    
        Script ConfigAuth
        {
            GetScript = {}
            TestScript = {Get-PswaAuthorizationRule}
            SetScript = {Add-PswaAuthorizationRule -UserName "boss" -ComputerName * -ConfigurationName Microsoft.PowerShell}
            # needs to run after newUser and PSWA
            DependsOn = newUser InstallPSWA
        }    
    }
}

