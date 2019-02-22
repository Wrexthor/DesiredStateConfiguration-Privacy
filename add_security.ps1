Configuration RemoveFeatures
# removes unsecure features not used by modern OS'es
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
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

# sets windows defender settings, preventing it from being disabled in the background
Configuration WinDefender
{
    Import-DscResource -ModuleName 'WindowsDefender'
    Node $env:COMPUTERNAME
    {
        WindowsDefender SetConfig
        {
            IsSingleInstance = 'Yes'
            RealTimeScanDirection = 'Both'
            RemediationScheduleDay = 'Everyday'
            SignatureScheduleDay = 'Everyday'
            MAPSReporting = 'Advanced'
            DisableBehaviorMonitoring = $true
            DisableIntrusionPreventionSystem = $true
            DisableIOAVProtection = $true
            DisableRealtimeMonitoring = $true
            DisableScriptScanning = $true
            DisableArchiveScanning = $true
            DisableCatchupFullScan = $true
            DisableCatchupQuickScan = $true
            DisableEmailScanning = $true
            DisableRemovableDriveScanning = $true
            DisableRestorePoint = $true
            DisableScanningMappedNetworkDrivesForFullScan = $true
            DisableScanningNetworkFiles = $true
            DisableBlockAtFirstSeen = $true
            CloudBlockLevel= 'Default'
            EnableNetworkProtection = 'Enabled'
            AttackSurfaceReductionRules_Actions = 'Enabled'
        }
    }
}


Configuration SetFirewall
{
    Import-DscResource -Module 'NetworkingDsc'
    Node $env:COMPUTERNAME
    {
    # sets firewall profiles
    FirewallProfile Private
    {
        Name = 'Private'
        Enabled = 'True'
        DefaultInboundAction = 'Block'
        DefaultOutboundAction = 'Allow'
        AllowInboundRules = 'True'
        # should be set to false if managed by GPO's or all settings are specified in DSC
        AllowLocalFirewallRules = 'True'        
        AllowUnicastResponseToMulticast = 'False'
        NotifyOnListen = 'True'
        LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
        LogMaxSizeKilobytes = 32767
        LogAllowed = 'True'
        LogBlocked = 'True'        
    }

    FirewallProfile Public
    {
        Name = 'Public'
        Enabled = 'True'
        DefaultInboundAction = 'Block'
        DefaultOutboundAction = 'Allow'
        AllowInboundRules = 'True'
        # should be set to false if managed by GPO's or all settings are specified in DSC
        AllowLocalFirewallRules = 'True'        
        AllowUnicastResponseToMulticast = 'False'
        NotifyOnListen = 'True'
        LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
        LogMaxSizeKilobytes = 32767
        LogAllowed = 'True'
        LogBlocked = 'True'        
    }

    FirewallProfile Domain
    {
        Name = 'Domain'
        Enabled = 'True'
        DefaultInboundAction = 'Block'
        DefaultOutboundAction = 'Allow'
        AllowInboundRules = 'True'
        # should be set to false if managed by GPO's or all settings are specified in DSC
        AllowLocalFirewallRules = 'True'        
        AllowUnicastResponseToMulticast = 'False'
        NotifyOnListen = 'True'
        LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
        LogMaxSizeKilobytes = 32767
        LogAllowed = 'True'
        LogBlocked = 'True'        
    }
    # blocks outbound programms commonly used by attackers
    # see https://lolbas-project.github.io/#/download
    # and https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb
    Firewall BlockOutExpand32bit
    {
        Name = 'BlockExpand32bit'
        DisplayName = 'BlockExpand32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\Expand.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutExpand
    {
        Name = 'BlockExpand'
        DisplayName = 'BlockExpand'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\Expand.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutExtrac
    {
        Name = 'BlockExtrac'
        DisplayName = 'BlockExtrac'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\extrac32.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutExtrac32bit
    {
        Name = 'BlockExtrac32bit'
        DisplayName = 'BlockExtrac32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\extrac32.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutFindstr32bit
    {
        Name = 'BlockFindstr32bit'
        DisplayName = 'BlockFindstr32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\findstr.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutFindstr
    {
        Name = 'BlockFindstr'
        DisplayName = 'BlockFindstr'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\findstr.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutHh
    {
        Name = 'BlockHh'
        DisplayName = 'BlockHh'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\hh.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutHh32bit
    {
        Name = 'BlockHh32bit'
        DisplayName = 'BlockHh32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWow64\hh.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutBitsAdmin
    {
        Name = 'BlockBitsAdmin'
        DisplayName = 'BlockBitsAdmin'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\bitsadmin.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutBitsAdmin32bit
    {
        Name = 'BlockBitsAdmin32bit'
        DisplayName = 'BlockBitsAdmin32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\bitsadmin.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCertUtil
    {
        Name = 'BlockCertUtil'
        DisplayName = 'BlockCertUtil'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\certutil.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCertUtil32bit
    {
        Name = 'BlockCertUtil32bit'
        DisplayName = 'BlockCertUtil32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\certutil.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutEsentUtl
    {
        Name = 'BlockEsentUtl'
        DisplayName = 'BlockEsentUtl'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\esentutl.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutEsentUtl32bit
    {
        Name = 'BlockEsentUtl32bit'
        DisplayName = 'BlockEsentUtl32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\esentutl.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutIeexec32bit
    {
        Name = 'BlockIeexec32bit'
        DisplayName = 'BlockIeexec32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutIeexec
    {
        Name = 'BlockIeexec'
        DisplayName = 'BlockIeexec'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Microsoft.NET\Framework\v2.0.50727\ieexec.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutMakecab32bit
    {
        Name = 'BlockMakecab32bit'
        DisplayName = 'BlockMakecab32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\makecab.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutMakecab
    {
        Name = 'BlockMakecab'
        DisplayName = 'BlockMakecab'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\makecab.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutReplace32bit
    {
        Name = 'BlockReplace32bit'
        DisplayName = 'BlockReplace32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\SysWOW64\replace.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutReplace
    {
        Name = 'BlockReplace'
        DisplayName = 'BlockReplace'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\replace.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutNotepad32bit
    {
        Name = 'BlockNotepad32bit'
        DisplayName = 'BlockNotepad32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\notepad.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutNotepad
    {
        Name = 'BlockNotepad'
        DisplayName = 'BlockNotepad'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\notepad.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCalc32bit
    {
        Name = 'BlockCalc32bit'
        DisplayName = 'BlockCalc32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\calc.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCalc
    {
        Name = 'BlockCalc'
        DisplayName = 'BlockCalc'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\calc.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutConhost32bit
    {
        Name = 'BlockConhost32bit'
        DisplayName = 'BlockConhost32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\conhost.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutConhost
    {
        Name = 'BlockConhost'
        DisplayName = 'BlockConhost'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\conhost.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCscript32bit
    {
        Name = 'BlockCscrip32bit'
        DisplayName = 'BlockCscript32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\cscript.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutCscript
    {
        Name = 'BlockCscrip'
        DisplayName = 'BlockCscript'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\cscript.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutWscript32bit
    {
        Name = 'BlockWscrip32bit'
        DisplayName = 'BlockWscript32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\wscript.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutWscript
    {
        Name = 'BlockWscrip'
        DisplayName = 'BlockWscript'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\wscript.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutMshta32bit
    {
        Name = 'BlockMshta32bit'
        DisplayName = 'BlockMshta32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\mshta.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutMshta
    {
        Name = 'BlockMshta'
        DisplayName = 'BlockMshta'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\mshta.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutRunScriptHelper32bit
    {
        Name = 'BlockRunScriptHelper32bit'
        DisplayName = 'BlockRunScriptHelper32bit'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\Syswow64\runscripthelper.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
    Firewall BlockOutRunScriptHelper
    {
        Name = 'BlockRunScriptHelper'
        DisplayName = 'BlockRunScriptHelper'
        Ensure = 'Present'        
        Enabled = 'True'
        Action = 'Block'
        Profile = ('Domain', 'Private', 'Public')
        Direction = 'OutBound'
        Program = '%SystemRoot%\System32\runscripthelper.exe'
        # remote address can be set to proxy for denying internet access but allowing lan/internal access
        #RemoteAddress = 'x.x.x.x/24'
    }
  }
}

RemoveFeatures
WinDefender
SetFirewall
