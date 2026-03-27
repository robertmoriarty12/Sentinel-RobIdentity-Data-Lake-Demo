# RobDentity × Microsoft Sentinel — Long-Horizon Identity Persistence Detection

## The Story

> *RobDentity's own detection engine saw a medium-severity anomaly in February 2026. The agent read 12 months of RobDentity's raw telemetry in Sentinel — the same data RobDentity generated but couldn't retain — and found a staged persistence campaign that started in September 2025. Entra, Azure Activity, and MDE independently confirm every signal. The detection is impossible in 30 days. It's unambiguous at 12 months.*

## The Problem

RobDentity is an identity risk management platform. Like Entra ID Protection and most identity SaaS vendors, **RobDentity retains raw identity telemetry for only 30 days**. Their detection engine operates within that window. This is not unique to RobDentity — it is the default retention posture of the identity SaaS market.

This means slow-burn identity persistence campaigns — where an attacker gradually expands access and drifts behavior over months — are **structurally undetectable** in any identity ISV's native platform.

Microsoft Sentinel Data Lake changes this. By streaming RobDentity telemetry into Sentinel, the ISV's data survives beyond their native retention window. An AI agent can then read 12 months of that data and produce detections that **RobDentity's own engine cannot generate** — not because the data was missing, but because the ISV couldn't keep it.

## Lab Contents

| Lab | Title | Purpose |
|-----|-------|---------|
| [Lab 1](./Labs/01-Sentinel-DataLake-Onboarding.md) | Sentinel Data Lake Onboarding | Onboard your tenant to the Sentinel Data Lake |
| [Lab 2](./Labs/02-RobDentity-Data-Connector.md) | RobDentity Data Connector | Deploy DCR/DCE pipeline and load 12 months of RobDentity identity telemetry |
| [Lab 3](./Labs/03-KQL-Jobs-Corroborating-Signals.md) | Corroborating Signal Tables | Load Entra, Azure Activity, and MDE signal tables via KQL jobs |
| Lab 4 *(coming soon)* | Building the Detection Agent | Build a Foundry agent that produces long-horizon persistence detections |

## The Attack Scenario: `alex.smith@contoso.com`

A staged identity persistence campaign spanning September 2025 → March 2026.

- **Months 1–6** (March–August 2025): Clean baseline. Chicago logins, managed device, standard hours, 3 business apps, Reader role only.
- **Inflection point**: September 1, 2025 — first anomalous event. Unmanaged Linux device appears.
- **Months 7–12** (September 2025–March 2026): Gradual privilege expansion, device trust erosion, off-hours escalation, datacenter IP authentication, app footprint expansion.
- **RobDentity's finding**: One Medium alert in February 2026 — "off-hours login anomaly." Dismissed as noise. Window: 30 days.
- **Agent detection**: Critical. Staged persistence. 6 converging signals. Window: 12 months. Confidence: 0.96.

## Data Architecture

```
RobDentity_RawEvents_CL    ← ISV's proprietary raw telemetry (Lab 2, DCR/DCE)
RobDentity_Findings_CL     ← ISV's own 30-day findings (Lab 2, DCR/DCE)
EntraSigninLogs_KQL_CL     ← Microsoft Entra sign-in history (Lab 3, KQL job)
AzureRoleChanges_KQL_CL    ← Azure RBAC change history (Lab 3, KQL job)
MDE_NetworkEvents_KQL_CL   ← MDE network connection events (Lab 3, KQL job)
```

## Repository Structure

```
Microsoft-Sentinel-Lake-Agent/
├── Labs/
│   ├── 01-Sentinel-DataLake-Onboarding.md
│   ├── 02-RobDentity-Data-Connector.md
│   ├── 03-KQL-Jobs-Corroborating-Signals.md
│   └── 04-Building-the-Detection-Agent.md  ← coming soon
├── RobDentity-Connector/
│   ├── deploy-arm-template.json       ← DCR/DCE/table deployment
│   └── generate_and_ingest.py         ← synthetic data generator + ingestion
├── KQL-Jobs/
│   ├── EntraSigninLogs
│   ├── AzureRoleChanges
│   └── MDE_NetworkEvents
└── Demo-Queries/
    └── detection-demo.kql             ← 5 KQL queries showing the ISV win
```
