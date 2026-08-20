@description('Name of the Log Analytics workspace enabled for Microsoft Sentinel')
param workspace string

resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspace
}

// The saved-search IDs must match the IDs used by the four hunting-query
// Bicep templates.
var relatedQueries = [
  {
    relationId: 'd1b2c3d4-0001-4444-8888-000000000001'
    savedSearchId: 'a1b2c3d4-0001-4444-8888-000000000001'
    label: 'LSASS Memory Access'
  }
  {
    relationId: 'd1b2c3d4-0002-4444-8888-000000000002'
    savedSearchId: 'a1b2c3d4-0002-4444-8888-000000000002'
    label: 'Registry Hive Dumping'
  }
  {
    relationId: 'd1b2c3d4-0003-4444-8888-000000000003'
    savedSearchId: 'a1b2c3d4-0003-4444-8888-000000000003'
    label: 'Browser Credential Access'
  }
  {
    relationId: 'd1b2c3d4-0004-4444-8888-000000000004'
    savedSearchId: 'a1b2c3d4-0004-4444-8888-000000000004'
    label: 'Credential Dumping Tools'
  }
]

// A Sentinel Hunt represents the working hypothesis.
resource credentialAccessHypothesis 'Microsoft.SecurityInsights/hunts@2025-07-01-preview' = {
  scope: sentinelWorkspace
  name: 'c8b5de8d-a99f-4f47-bdd9-38ee5b8f8c01'

  properties: {
    displayName: 'Credential Access and Credential Dumping Activity'

    description: '''
Hypothesis: Threat actors might be attempting to acquire credentials from endpoints by accessing LSASS memory, exporting registry hives, accessing browser credential stores, or using known credential-dumping tools.

The hunt investigates:

1. LSASS memory access consistent with credential dumping.
2. Export of SAM, SECURITY, and SYSTEM registry hives.
3. Suspicious access to browser credential stores.
4. Command-line and file indicators associated with credential-dumping tools.

Expected outcome:

Determine whether credential-access activity occurred, identify affected devices and accounts, preserve relevant evidence, and create incidents or additional analytics rules when required.
'''

    // Hunt workflow state.
    status: 'Active'

    // Supported values: Unknown, Validated, Invalidated.
    hypothesisStatus: 'Unknown'

    attackTactics: [
      'CredentialAccess'
    ]

    attackTechniques: [
      'T1003'
      'T1003.001'
      'T1003.002'
      'T1555.003'
    ]

    labels: [
      'GitHub'
      'Credential Access'
      'Credential Dumping'
      'Automated deployment'
    ]
  }
}

// Associate all four saved hunting queries with the Hunt.
resource queryRelations 'Microsoft.SecurityInsights/hunts/relations@2025-07-01-preview' = [
  for relatedQuery in relatedQueries: {
    parent: credentialAccessHypothesis
    name: relatedQuery.relationId

    properties: {
      relatedResourceId: resourceId(
        'Microsoft.OperationalInsights/workspaces/savedSearches',
        workspace,
        relatedQuery.savedSearchId
      )

      labels: [
        'HuntingQuery'
        relatedQuery.label
      ]
    }
  }
]

output huntName string = credentialAccessHypothesis.properties.displayName
output huntResourceId string = credentialAccessHypothesis.id
output hypothesisStatus string = credentialAccessHypothesis.properties.hypothesisStatus
output relatedQueryCount int = length(relatedQueries)
