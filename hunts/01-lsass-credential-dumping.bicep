param workspace string

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${workspace}/a1b2c3d4-0001-4444-8888-000000000001'
  location: resourceGroup().location
  properties: {
    eTag: '*'
    displayName: 'LSASS Memory Access (Credential Dumping)'
    category: 'Hunting Queries'
    query: '''
DeviceProcessEvents
| where FileName in~ ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe", "werfault.exe")
| where ProcessCommandLine has_any ("lsass", "comsvcs.dll", "MiniDump")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated desc
'''
    version: 1
    tags: [
      {
        name: 'description'
        value: 'Detects processes accessing LSASS memory in patterns consistent with credential dumping tools (procdump, comsvcs.dll MiniDump technique).'
      }
      {
        name: 'tactics'
        value: 'CredentialAccess'
      }
      {
        name: 'relevantTechniques'
        value: 'T1003.001'
      }
    ]
  }
}
