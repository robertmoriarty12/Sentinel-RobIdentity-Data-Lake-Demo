# Lab 2: Deploy the RobDentity Data Connector

**ISV:** RobDentity — Identity Risk Management Platform

## The ISV Limitation This Lab Addresses

RobDentity retains raw identity telemetry for **30 days**. This is not a product deficiency — it is the standard retention posture across the identity SaaS market. Microsoft Entra ID Protection does the same.

Within 30 days, RobDentity's detection engine can surface point-in-time anomalies. What it cannot do is compare today's behavior against a 6–12 month behavioral baseline. Slow-burn persistence campaigns — where an attacker gradually expands access and shifts authentication patterns over months — are **structurally undetectable** in any 30-day window.

This lab deploys a data connector that streams RobDentity's telemetry into the Sentinel Data Lake. Once there, Sentinel retains it for 12 months. The agent in Lab 4 reads from this long-term store to produce detections that **RobDentity's own engine cannot generate** — not because the data was missing, but because RobDentity couldn't keep it.

## What Gets Deployed

| Component | Name | Purpose |
|-----------|------|---------|
| Data Collection Endpoint | `robdentity-dce` | HTTPS ingestion endpoint RobDentity pushes data to |
| Data Collection Rule | `RobDentity-DCR` | Routes incoming data to the correct Sentinel tables |
| Sentinel Table | `RobDentity_RawEvents_CL` | RobDentity's raw identity session telemetry — 12 months |
| Sentinel Table | `RobDentity_Findings_CL` | RobDentity's own 30-day findings — proving their engine's limitation |

## The Data

### `RobDentity_RawEvents_CL` Schema

The ISV's proprietary processed telemetry — what their platform generates per identity session.

| Field | Type | Description |
|-------|------|-------------|
| `createdDateTime` | datetime | Event timestamp (RobDentity's schema, not TimeGenerated) |
| `UserPrincipalName` | string | Identity under observation |
| `UserId` | string | RobDentity internal user ID |
| `EventType` | string | SignIn / AppAccess / AdminAction / TokenRefresh |
| `LoginGeo_Country` | string | Country of authentication |
| `LoginGeo_City` | string | City of authentication |
| `IPAddress` | string | Source IP address |
| `AuthNetworkCategory` | string | CorporateVPN / DatacenterIP / Residential / TorExit |
| `DeviceId` | string | Device fingerprint |
| `DeviceTrustType` | string | Managed / Unmanaged |
| `DevicePlatform` | string | Windows / macOS / Linux |
| `ApplicationAccessed` | string | Application accessed during session |
| `ResourceAccessed` | string | Azure resource accessed |
| `AuthMethod` | string | MFA / SSO / PasswordOnly |
| `MFAResult` | string | Approved / Challenged / Bypassed |
| `DataVolumeKB` | long | Data transferred during session |
| `SessionDurationSeconds` | long | Session length |
| `RolesHeldAtTime` | dynamic | Snapshot of RBAC roles held at time of session |
| `RobDentity_RiskScore` | real | RobDentity's per-event risk score (0–100) |
| `RobDentity_EventFlag` | string | Normal / Drift / Suspicious / Critical |

### `RobDentity_Findings_CL` Schema

RobDentity's own platform findings — what their 30-day detection engine surfaces.

| Field | Type | Description |
|-------|------|-------------|
| `createdDateTime` | datetime | Finding timestamp |
| `UserPrincipalName` | string | Identity the finding is about |
| `FindingId` | string | RobDentity unique finding ID |
| `FindingType` | string | Detection category |
| `Severity` | string | Low / Medium / High / Critical |
| `Description` | string | Finding description |
| `TriggeredBy` | string | Which RobDentity detector fired |
| `RobDentity_WindowUsed` | string | **Always "30d"** — the ISV's retention limit |
| `Confidence` | real | RobDentity confidence score |
| `Disposition` | string | Open / Dismissed / Escalated |

> **Why `RobDentity_WindowUsed` matters:** Every RobDentity finding in this dataset has `RobDentity_WindowUsed = "30d"`. The agent in Lab 4 uses `createdDateTime > ago(365d)` and produces a Critical detection with `ComparisonWindow = "12 months"`. Same underlying data. Different retention window. Better detection.

## The Scenario Users

| User | Scenario | What's in their data |
|------|----------|---------------------|
| `alex.smith@contoso.com` | **Staged persistence** | Clean 6-month baseline, then 6-month gradual drift across 5 independent signals |
| `sam.lee@contoso.com` | Legitimate geo travel | New country logins — device stays managed, risk stays low. False positive contrast. |
| `priya.nair@contoso.com` | Completely stable | No anomalies. Clean baseline across all 12 months. |

## Prerequisites

- Lab 1 (Sentinel Data Lake Onboarding) complete
- Azure subscription with Contributor access to the resource group
- An App Registration with `Monitoring Metrics Publisher` role on the DCR (created in Step 3 below)
- Python 3.8+ with pip

## Step 1: Create App Registration

This App Registration is the credential RobDentity (or the data generator script) uses to authenticate to the ingestion endpoint.

#### Azure CLI

```bash
APP_NAME="RobDentity-Sentinel-Connector"
APP_ID=$(az ad app create --display-name $APP_NAME --query appId -o tsv)
az ad sp create --id $APP_ID
SECRET=$(az ad app credential reset --id $APP_ID --append --query password -o tsv)

echo "Client ID:     $APP_ID"
echo "Tenant ID:     $(az account show --query tenantId -o tsv)"
echo "Client Secret: $SECRET"
```

> **Save these values immediately.** The client secret cannot be retrieved after this step.

#### PowerShell

```powershell
$app    = New-AzADApplication -DisplayName "RobDentity-Sentinel-Connector"
$sp     = New-AzADServicePrincipal -ApplicationId $app.AppId
$secret = New-AzADAppCredential -ApplicationId $app.AppId -EndDate (Get-Date).AddYears(1)

Write-Host "Client ID:     $($app.AppId)"
Write-Host "Tenant ID:     $((Get-AzContext).Tenant.Id)"
Write-Host "Client Secret: $($secret.SecretText)"
```

## Step 2: Deploy the ARM Template

Deploys the Data Collection Endpoint, Data Collection Rule, and both Sentinel tables.

#### Azure CLI

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file RobDentity-Connector/deploy-arm-template.json \
  --parameters workspaceName=<your-sentinel-workspace-name>
```

#### PowerShell

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<your-resource-group>" `
  -TemplateFile "RobDentity-Connector\deploy-arm-template.json" `
  -workspaceName "<your-sentinel-workspace-name>"
```

Deployment takes 2–5 minutes.

## Step 3: Capture Deployment Outputs

After deployment, capture the output values — you'll need them for the ingestion script.

#### Azure CLI

```bash
az deployment group show \
  --resource-group <your-resource-group> \
  --name deploy-arm-template \
  --query "properties.outputs"
```

Save these four values:

| Output | Use |
|--------|-----|
| `dataCollectionEndpointUrl` | Set as `DCE_ENDPOINT` in the script |
| `dataCollectionRuleImmutableId` | Set as `DCR_IMMUTABLE_ID` in the script |
| `rawEventsStreamName` | `Custom-RobDentity_RawEvents_CL` |
| `findingsStreamName` | `Custom-RobDentity_Findings_CL` |

## Step 4: Assign Permissions

Grant the App Registration the `Monitoring Metrics Publisher` role on the Data Collection Rule.

```bash
DCR_ID="/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/RobDentity-DCR"
SP_ID=$(az ad sp show --id $APP_ID --query id -o tsv)

az role assignment create \
  --assignee $SP_ID \
  --role "Monitoring Metrics Publisher" \
  --scope $DCR_ID
```

Wait 2–3 minutes for role propagation before running the ingestion script.

## Step 5: Install Python Dependencies

```bash
pip install azure-identity azure-monitor-ingestion
```

## Step 6: Configure and Run the Data Generator

Open `RobDentity-Connector/generate_and_ingest.py` and fill in the configuration section:

```python
TENANT_ID     = "your-tenant-id"
CLIENT_ID     = "your-client-id"        # From Step 1
CLIENT_SECRET = "your-client-secret"    # From Step 1

DCE_ENDPOINT      = "https://your-dce-endpoint.ingest.monitor.azure.com"  # From Step 3
DCR_IMMUTABLE_ID  = "dcr-xxxxxxxxxxxxxxxx"                                  # From Step 3
```

Then run:

```bash
python RobDentity-Connector/generate_and_ingest.py
```

Expected output:

```
======================================================================
RobDentity Synthetic Data Generator
Generating 12 months of identity telemetry (Mar 2025 – Mar 2026)
======================================================================

[1/2] Generating RobDentity_RawEvents_CL ...
      Generated ~900 raw event records across 3 users

[2/2] Generating RobDentity_Findings_CL ...
      Generated 3 findings records

Ingesting RobDentity_RawEvents_CL ...
  ✓ Sent 500/900 records to Custom-RobDentity_RawEvents_CL
  ✓ Sent 900/900 records to Custom-RobDentity_RawEvents_CL

Ingesting RobDentity_Findings_CL ...
  ✓ Sent 3/3 records to Custom-RobDentity_Findings_CL

======================================================================
✓ Ingestion complete.
  Note: Data may take 5–20 minutes to appear in Sentinel.

  To verify in Sentinel Data Lake Exploration:
  RobDentity_RawEvents_CL | summarize count() by UserPrincipalName
  RobDentity_Findings_CL  | project createdDateTime, UserPrincipalName, Severity, Disposition
======================================================================
```

## Step 7: Verify Data in Sentinel

Wait 5–20 minutes for initial indexing, then open **Data Lake Exploration** in the Defender portal.

**Verify record counts per user:**
```kql
RobDentity_RawEvents_CL
| summarize Events=count(), AvgRiskScore=avg(RobDentity_RiskScore)
    by UserPrincipalName
```

**Verify RobDentity's own findings — note the 30-day window limitation:**
```kql
RobDentity_Findings_CL
| project createdDateTime, UserPrincipalName, Severity, RobDentity_WindowUsed, Disposition, Description
| order by createdDateTime asc
```

**Preview the risk score progression for alex.smith (the story in one query):**
```kql
RobDentity_RawEvents_CL
| where UserPrincipalName == "alex.smith@contoso.com"
| summarize AvgRiskScore=avg(RobDentity_RiskScore), Sessions=count()
    by Month=format_datetime(createdDateTime, "yyyy-MM")
| order by Month asc
```

This query will show the gradual risk score escalation from ~12 in March 2025 to ~60+ by March 2026 — a pattern that only resolves into a meaningful detection at 12-month scale.

---

**Next:** [Lab 3 — Load Corroborating Signal Tables via KQL Jobs](./03-KQL-Jobs-Corroborating-Signals.md)
