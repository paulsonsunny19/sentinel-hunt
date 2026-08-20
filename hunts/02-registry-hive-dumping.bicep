param workspace string

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${workspace}/a1b2c3d4-0002-4444-8888-000000000002'
  location: resourceGroup().location
  properties: {
    eTag: '*'
    displayName: 'SAM/SECURITY/SYSTEM Registry Hive Dumping'
    category: 'Hunting Queries'
    query: '''
DeviceProcessEvents
| where FileName in~ ("reg.exe")
| where ProcessCommandLine has "save"
| where ProcessCommandLine has_any ("HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, FolderPath
| order by TimeGenerated desc
'''
    version: 1
    tags: [
      {
        name: 'description'
        value: 'Detects use of reg.exe to save the SAM, SECURITY, or SYSTEM registry hives, a common technique for offline extraction of local credential material.'
      }
      {
        name: 'tactics'
        value: 'CredentialAccess'
      }
      {
        name: 'relevantTechniques'
        value: 'T1003.002'
      }
    ]
  }
}
