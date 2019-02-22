Configuration MetaConfig
# sets the configuraiton for DSC to check and if needed, reapply the config every 60 minutes
{
    Node $env:COMPUTERNAME
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 60
            RebootNodeIfNeeded = $false
        }
    }
}
# run config
MetaConfig