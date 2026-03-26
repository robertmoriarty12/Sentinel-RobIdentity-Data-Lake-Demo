# Lab 1: Sentinel Data Lake Onboarding

## Overview

This lab guides you through onboarding your tenant to the Microsoft Sentinel Data Lake from the Microsoft Defender portal.

Before you deploy RobDentity's data connector or load any sample data, the Sentinel Data Lake must be active. The onboarding process provisions the lake in your subscription and enables Data Lake Exploration — the query surface the agent in Lab 4 uses to read 12 months of identity telemetry.

> **Why this matters for RobDentity:** RobDentity retains raw identity telemetry for **30 days**. Once onboarded, Sentinel becomes the long-term memory layer — retaining RobDentity telemetry for up to 12 months. The agent in Lab 4 reads from this layer to produce detections that are structurally impossible inside RobDentity's native platform.

## Prerequisites

### Required Permissions
- Global Administrator **or** Security Administrator in Microsoft Entra ID
- **AND** Subscription Owner **or** User Access Administrator (Azure IAM)
- **AND** Microsoft Sentinel Contributor role

### Required Access
- Microsoft Defender portal: https://security.microsoft.com/

## Step-by-Step Onboarding

### Step 1: Sign In to Defender Portal
1. Navigate to **https://security.microsoft.com/**
2. Sign in with credentials that have the required permissions above

### Step 2: Initiate Data Lake Onboarding
1. Look for a banner at the top of the Defender portal home page indicating you can onboard to the Microsoft Sentinel Data Lake
2. Click **"Get started"** on the banner
   - *Alternative:* Navigate to **System > Settings > Microsoft Sentinel > Data lake**

![Microsoft Sentinel DataLake Settings](./Images/Data%20Lake%20Onboarding-1.png)

### Step 3: Connect SIEM Workspace
1. If the required permissions are not in place, the Sentinel workspace will not appear in the list
2. Select your workspace, click **Connect workspace**, and set it as **Primary**

![Microsoft SIEM Workspace](./Images/Data%20Lake%20Onboarding-2.png)

### Step 4: Select Subscription and Resource Group
1. Click **Start setup** under **Data lake**
   - If permissions are missing, the side panel will indicate which are absent

![Microsoft Data lake setup](./Images/Data%20Lake%20Onboarding-3.png)

2. Select your target **Subscription** from the dropdown
3. Select the target **Resource group**
4. Click **Set up data lake**

![Microsoft Data lake setup](./Images/Data%20Lake%20Onboarding-4.png)

### Step 5: Monitor Onboarding Progress
1. The setup process displays a progress panel
2. Onboarding can take **up to 60 minutes** — you can safely close the panel while it runs
3. A "Setup in progress" banner appears on the Defender portal home page

### Step 6: Verify Completion
1. Once complete, a new banner appears with information cards
2. Confirm **Data lake exploration** is visible under **Microsoft Sentinel**

![Microsoft Sentinel Data lake exploration](./Images/Data%20Lake%20Onboarding-5.png)

**Reference:** [Microsoft Docs — Onboard to Microsoft Sentinel data lake](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-onboard-defender)

---

**Next:** [Lab 2 — Deploy the RobDentity Data Connector](./02-RobDentity-Data-Connector.md)
