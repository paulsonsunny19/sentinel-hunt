param workspace string

resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspace
}

var relatedQueries = [
  {
    relationId: 'd1b2c3d4-0001-4444-8888-000000000001'
    savedSearchId: 'a1b2c3d4-0001-4444-8888-000000000001'
  }
  {
    relationId: 'd1b2c3d4-0002-4444-8888-000000000002'
    savedSearchId: 'a1b2c3d4-0002-4444-8888-000000000002'
  }
  {
    relationId: 'd1b2c3d4-0003-4444-8888-000000000003'
    savedSearchId: 'a1b2c3d4-0003-4444-8888-000000000003'
  }
  {
    relationId: 'd1b2c3d4-0004-4444-8888-000000000004'
    savedSearchId: 'a1b2c3d4-0004-4444-8888-000000000004'
  }
]

resource credentialAccessHypothesis 'Microsoft.SecurityInsights/hunts@2025-07-01-preview' = {
  scope: sentinelWorkspace
  name: 'c8b5de8d-a99f-4f47-bdd9-38ee5b8f8c01'

  properties: {
    displayName: 'Credential Access and Credential Dumping Activity'

    description: '''
Hypothesis: Threat actors might be attempting to acquire credentials from endpoints by accessing LSASS memory, exporting registry hives, accessing browser credential stores, or using known credential-dumping tools.

The hunt investigates:
1. LSASS memory access.
2. SAM, SECURITY, and SYSTEM hive dumping.
3. Browser credential-store access.
4. Known credential-dumping tool signatures.
'''

    status: 'Active'
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
      'Automated deployment'
    ]
  }
}

resource queryRelations 'Microsoft.SecurityInsights/hunts/relations@2025-07-01-preview' = [
  for relatedQuery in relatedQueries: {
    parent: credentialAccessHypothesis
    name: relatedQuery.relationId

    properties: {
      relatedResourceId: resourceId(
        'Microsoft.OperationalInsights/workspaces/savedSearches'
        workspace
        relatedQuery.savedSearchId
      )

      labels: [
        'HuntingQuery'
      ]
    }
  }
]

output huntResourceId string = credentialAccessHypothesis.id
