# Lab 3: Load Corroborating Signal Tables via KQL Jobs

## Purpose

This lab loads three Microsoft-native and MDE signal tables into the Sentinel Data Lake using KQL jobs. These tables represent telemetry a customer would already have in their SIEM — Entra sign-in logs, Azure RBAC activity, and MDE network events.

The agent in Lab 4 reads all five tables (two from RobDentity, three from here) and finds that **three independent Microsoft sources confirm the exact same inflection point** that RobDentity's raw telemetry identified: September 1, 2025.

That convergence — the same behavioral shift seen identically in identity, authorization, and endpoint telemetry — is what makes the detection unambiguous. And it is only possible at 12-month scale.

## What Each Table Adds to the Story

| Table | Signal Layer | Key Contribution |
|-------|-------------|-----------------|
| `EntraSigninLogs_KQL_CL` | Identity (Microsoft) | Independently confirms the unmanaged Linux device and European geo shift starting Sep 2025. Entra's own 30-day risk signals only fired in isolated months; the 12-month view shows the pattern. |
| `AzureRoleChanges_KQL_CL` | Authorization (Azure) | Authoritative record of 4 privilege additions between Sep 2025 and Jan 2026. Shows that access expansion **preceded** the behavioral escalation peaks — the attacker acquired permissions before exploiting them. |
| `MDE_NetworkEvents_KQL_CL` | Endpoint (MDE) | Outbound `azcopy.exe` and `az.exe` connections to datacenter IPs at 2–4am, precisely aligned with `DatacenterIP` sessions in RobDentity raw events. Endpoint evidence corroborates auth-layer signals. |

## Prerequisites

- Lab 1 (Sentinel Data Lake Onboarding) complete
- Lab 2 (RobDentity Data Connector) complete
- Security Administrator or Security Operator role

## How to Create KQL Jobs

For each table below, follow this process in the Sentinel Data Lake Exploration portal:

1. Navigate to **Microsoft Sentinel → Data lake exploration → Jobs**
2. Click **Create a new KQL job**
3. Enter a **Job name** (suggested names provided per table below)
4. Enter a **Job description**
5. Select your **workspace**
6. Under destination, select **Create a new table** and enter the table name exactly as shown
7. Copy the KQL query from the corresponding file in `KQL-Jobs/`
8. Set schedule to **Scheduled**, repeat **every 1 day** (or run once — this is sample data)
9. Review and **Submit**

> **Note:** Tables created by KQL jobs have `_KQL_CL` appended automatically. Enter only the base name (e.g., `EntraSigninLogs`) and the full name becomes `EntraSigninLogs_KQL_CL`.

---

## Table 1: EntraSigninLogs_KQL_CL

**Job name:** `EntraSigninLogs-12Month-Sample`

**Description:** 12 months of Entra sign-in logs for 3 users. Corroborates RobDentity geo and device shift signals from Microsoft's perspective.

**KQL file:** [`KQL-Jobs/EntraSigninLogs`](../KQL-Jobs/EntraSigninLogs)

**Verify after ingestion:**
```kql
EntraSigninLogs_KQL_CL
| summarize SignIns=count(), Countries=dcount(tostring(Location.countryOrRegion))
    by UserPrincipalName
```

**Story query — shows Entra independently confirming the inflection:**
```kql
EntraSigninLogs_KQL_CL
| where UserPrincipalName == "alex.smith@contoso.com"
| extend Country = tostring(Location.countryOrRegion),
         IsManaged = tostring(DeviceDetail.isManaged)
| project createdDateTime, Country, IsManaged, RiskLevelAggregated, RiskState
| order by createdDateTime asc
```

---

## Table 2: AzureRoleChanges_KQL_CL

**Job name:** `AzureRoleChanges-12Month-Sample`

**Description:** Azure RBAC assignment history for 12 months. Shows 4 privilege additions to alex.smith between Sep 2025 and Jan 2026, each occurring 4–6 weeks apart to evade short-window privilege alerts.

**KQL file:** [`KQL-Jobs/AzureRoleChanges`](../KQL-Jobs/AzureRoleChanges)

**Verify after ingestion:**
```kql
AzureRoleChanges_KQL_CL
| summarize RoleAdditions=countif(OperationType == "Add")
    by UserPrincipalName
```

**Story query — shows privilege expansion timeline:**
```kql
AzureRoleChanges_KQL_CL
| where UserPrincipalName == "alex.smith@contoso.com"
    and OperationType == "Add"
| project createdDateTime, RoleDefinitionName, Scope
| order by createdDateTime asc
```

> **Key insight:** The first role addition (Sep 5, 2025 — Storage Blob Data Reader) occurs 4 days after the first unmanaged device login seen in both RobDentity and Entra data. The privilege preceded and enabled the behavioral escalation.

---

## Table 3: MDE_NetworkEvents_KQL_CL

**Job name:** `MDE-NetworkEvents-12Month-Sample`

**Description:** MDE network connection events from alex.smith's managed Windows device. Shows `azcopy.exe` and `az.exe` connections to datacenter IPs at off-hours timestamps, aligned with RobDentity DatacenterIP session events.

**KQL file:** [`KQL-Jobs/MDE_NetworkEvents`](../KQL-Jobs/MDE_NetworkEvents)

**Verify after ingestion:**
```kql
MDE_NetworkEvents_KQL_CL
| summarize Connections=count()
    by AccountName, InitiatingProcessFileName
```

**Story query — shows endpoint-level off-hours exfil activity:**
```kql
MDE_NetworkEvents_KQL_CL
| where AccountName == "alex.smith"
| extend Hour = datetime_part("hour", createdDateTime)
| project createdDateTime, Hour, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by createdDateTime asc
```

> **Key insight:** All suspicious connections occur between 01:00 and 04:00 UTC. `azcopy.exe` connections to external IPs in March 2026 are the endpoint-level confirmation of the backup exfiltration activity that RobDentity's DataVolumeKB spikes flagged in the same month.

---

## Cross-Table Validation Query

Once all three tables are ingested, run this in Data Lake Exploration to confirm all five tables are populated and ready for the agent in Lab 4:

```kql
let tables = datatable(TableName: string) [
    "RobDentity_RawEvents_CL",
    "RobDentity_Findings_CL",
    "EntraSigninLogs_KQL_CL",
    "AzureRoleChanges_KQL_CL",
    "MDE_NetworkEvents_KQL_CL"
];
tables
```

Then verify each individually with a simple count. All five should return records before proceeding to Lab 4.

---

## The Multi-Signal Picture Before Lab 4

At this point, the following is true across all five tables for `alex.smith@contoso.com`:

| Signal | First Anomaly Date | Source | Independently Confirms |
|--------|-------------------|--------|----------------------|
| Unmanaged Linux device | Sep 1, 2025 | `RobDentity_RawEvents_CL` | — |
| Unmanaged device login | Sep 1, 2025 | `EntraSigninLogs_KQL_CL` | ✓ |
| Storage Blob Reader role added | Sep 5, 2025 | `AzureRoleChanges_KQL_CL` | — |
| Off-hours datacenter IP connection | Sep 1, 2025 | `MDE_NetworkEvents_KQL_CL` | ✓ |
| Off-hours auth network = DatacenterIP | Sep 14, 2025 | `RobDentity_RawEvents_CL` | — |

Three independent Microsoft sources. Same inflection point. This is only visible at 12-month scale. In a 30-day window, each of these would appear as a single low-signal event — individually dismissible.

---

**Next:** [Lab 4 — Building the Detection Agent in Azure AI Foundry](./04-Building-the-Detection-Agent.md)
