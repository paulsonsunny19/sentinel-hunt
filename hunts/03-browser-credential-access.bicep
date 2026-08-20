param workspace string

resource huntingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${workspace}/a1b2c3d4-0003-4444-8888-000000000003'
  location: resourceGroup().location
  properties: {
    eTag: '*'
    displayName: 'Browser Credential Store Access'
    category: 'Hunting Queries'
    query: '''
DeviceFileEvents
| where FolderPath has_any ("AppData\\Local\\Google\\Chrome\\User Data", "AppData\\Local\\Microsoft\\Edge\\User Data", "AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
| where FileName in~ ("Login Data", "Login Data For Account", "key4.db", "logins.json", "cookies.sqlite")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project TimeGenerated, DeviceName, AccountName = InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
'''
    version: 1
    tags: [
      {
        name: 'description'
        value: 'Detects non-browser processes creating, modifying, or renaming browser credential store files, consistent with credential theft from local browser password stores.'
      }
      {
        name: 'tactics'
        value: 'CredentialAccess'
      }
      {
        name: 'relevantTechniques'
        value: 'T1555.003'
      }
    ]
  }
}
