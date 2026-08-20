param workspace string

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${workspace}/a1b2c3d4-0004-4444-8888-000000000004'
  location: resourceGroup().location
  properties: {
    eTag: '*'
    displayName: 'Known Credential Dumping Tool Signatures'
    category: 'Hunting Queries'
    query: '''
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "lsadump", "kerberos::golden", "kerberos::ptt", "privilege::debug", "mimikatz", "invoke-mimikatz")
    or FileName in~ ("mimikatz.exe", "mimidrv.sys", "pypykatz.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256
| order by TimeGenerated desc
'''
    version: 1
    tags: [
      {
        name: 'description'
        value: 'Detects command-line indicators and file names associated with known credential dumping tools such as Mimikatz and its variants.'
      }
      {
        name: 'tactics'
        value: 'CredentialAccess'
      }
      {
        name: 'relevantTechniques'
        value: 'T1003'
      }
    ]
  }
}
