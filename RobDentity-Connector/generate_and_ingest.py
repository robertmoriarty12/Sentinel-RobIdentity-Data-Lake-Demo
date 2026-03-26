"""
RobDentity Synthetic Data Generator & Ingestion Script
=======================================================
Generates 12 months of synthetic identity telemetry for 3 users and ingests
it into Microsoft Sentinel via the Azure Monitor Ingestion API (DCE/DCR).

SCENARIO: alex.smith@contoso.com undergoes a staged identity persistence
campaign beginning September 1, 2025. The other two users (sam.lee, priya.nair)
exhibit benign behavior for contrast.

RobDentity retains data for 30 days natively.
Sentinel retains this data for 12 months — enabling the long-horizon detection
that RobDentity's own engine cannot produce.

USAGE:
    1. Fill in the configuration section below
    2. pip install azure-identity azure-monitor-ingestion
    3. python generate_and_ingest.py
"""

import json
import random
import uuid
from typing import Optional
from datetime import datetime, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

# ===========================================================================
# CONFIGURATION — fill these in from your ARM deployment outputs
# ===========================================================================

DCE_ENDPOINT        = "https://robdentity-dce-b7p3.centralus-1.ingest.monitor.azure.com"
DCR_IMMUTABLE_ID    = "dcr-1400ef3a067145b9b5102053142ec723"

RAW_EVENTS_STREAM   = "Custom-RobDentity_RawEvents_CL"
FINDINGS_STREAM     = "Custom-RobDentity_Findings_CL"

# ===========================================================================
# SCENARIO PARAMETERS
# ===========================================================================

# Timeline: March 25 2025 → March 25 2026 (12 months)
BASELINE_START   = datetime(2025, 3, 25, tzinfo=timezone.utc)
INFLECTION_DATE  = datetime(2025, 9, 1,  tzinfo=timezone.utc)   # attack begins
END_DATE         = datetime(2026, 3, 25, tzinfo=timezone.utc)

# Events per user per month (approximate)
EVENTS_PER_MONTH = 25

# Users
USERS = {
    "alex.smith@contoso.com": {
        "id": "usr-alex-001",
        "scenario": "compromised",         # staged persistence
    },
    "sam.lee@contoso.com": {
        "id": "usr-sam-002",
        "scenario": "benign_travel",       # legitimate geo change, low risk
    },
    "priya.nair@contoso.com": {
        "id": "usr-priya-003",
        "scenario": "stable",              # completely clean baseline
    },
}

# ===========================================================================
# BASELINE PROFILE — clean behavior months 1-6 for all users
# ===========================================================================

BASELINE_PROFILES = {
    "alex.smith@contoso.com": {
        "country": "United States", "city": "Chicago",
        "hours": (8, 18),                          # 8am–6pm local
        "devices": [{"id": "dev-win-alex-001", "trust": "Managed", "platform": "Windows"}],
        "network": "CorporateVPN",
        "apps": ["Microsoft Teams", "SharePoint", "Outlook"],
        "resources": ["rg-corp-shared"],
        "roles": ["Reader"],
        "auth_method": "MFA",
        "data_volume_kb": (100, 800),
        "risk_score": (5, 18),
    },
    "sam.lee@contoso.com": {
        "country": "United States", "city": "Seattle",
        "hours": (9, 17),
        "devices": [{"id": "dev-mac-sam-001", "trust": "Managed", "platform": "macOS"}],
        "network": "CorporateVPN",
        "apps": ["Microsoft Teams", "Outlook", "Azure DevOps"],
        "resources": ["rg-dev-shared"],
        "roles": ["Reader", "DevOps Contributor"],
        "auth_method": "MFA",
        "data_volume_kb": (50, 600),
        "risk_score": (4, 15),
    },
    "priya.nair@contoso.com": {
        "country": "United States", "city": "Dallas",
        "hours": (8, 17),
        "devices": [{"id": "dev-win-priya-001", "trust": "Managed", "platform": "Windows"}],
        "network": "CorporateVPN",
        "apps": ["Microsoft Teams", "Outlook", "PowerBI"],
        "resources": ["rg-analytics"],
        "roles": ["Reader", "Analytics Contributor"],
        "auth_method": "MFA",
        "data_volume_kb": (80, 500),
        "risk_score": (3, 12),
    },
}

# ===========================================================================
# DRIFT PROFILE — what changes for alex.smith after inflection point
# The drift is GRADUAL — each month adds one more signal
# ===========================================================================

DRIFT_PHASES = [
    # (months_after_inflection, description, changes)
    {
        "after_month": 0,   # Sep 2025 — month 1 of drift
        "new_device": {"id": "dev-linux-unknown-001", "trust": "Unmanaged", "platform": "Linux"},
        "off_hours_pct": 0.08,    # 8% of sessions now off-hours
        "new_countries": [],
        "new_apps": [],
        "new_roles": [],
        "network_shift_pct": 0.0,
        "risk_boost": 8,
    },
    {
        "after_month": 1,   # Oct 2025
        "off_hours_pct": 0.14,
        "new_countries": [("Germany", "Frankfurt")],
        "new_apps": ["Azure Storage Explorer"],
        "new_roles": ["Storage Blob Data Reader"],
        "network_shift_pct": 0.10,   # 10% sessions from DatacenterIP
        "risk_boost": 15,
    },
    {
        "after_month": 2,   # Nov 2025
        "off_hours_pct": 0.22,
        "new_countries": [("Germany", "Frankfurt"), ("Netherlands", "Amsterdam")],
        "new_apps": ["Azure Storage Explorer", "Azure Key Vault"],
        "new_roles": ["Storage Blob Data Reader", "Key Vault Secrets User"],
        "network_shift_pct": 0.20,
        "risk_boost": 22,
    },
    {
        "after_month": 3,   # Dec 2025
        "off_hours_pct": 0.28,
        "new_countries": [("Germany", "Frankfurt"), ("Netherlands", "Amsterdam")],
        "new_apps": ["Azure Storage Explorer", "Azure Key Vault", "Azure Backup Center"],
        "new_roles": ["Storage Blob Data Reader", "Key Vault Secrets User", "Backup Contributor"],
        "network_shift_pct": 0.30,
        "risk_boost": 30,
    },
    {
        "after_month": 4,   # Jan 2026
        "off_hours_pct": 0.31,
        "new_countries": [("Germany", "Frankfurt"), ("Netherlands", "Amsterdam"), ("Ukraine", "Kyiv")],
        "new_apps": ["Azure Storage Explorer", "Azure Key Vault", "Azure Backup Center", "Azure Resource Manager"],
        "new_roles": ["Storage Blob Data Reader", "Key Vault Secrets User", "Backup Contributor", "Contributor"],
        "network_shift_pct": 0.38,
        "risk_boost": 38,
    },
    {
        "after_month": 5,   # Feb 2026 — month where RobDentity fires a medium alert (30-day window only sees this one)
        "off_hours_pct": 0.34,
        "new_countries": [("Germany", "Frankfurt"), ("Netherlands", "Amsterdam"), ("Ukraine", "Kyiv")],
        "new_apps": ["Azure Storage Explorer", "Azure Key Vault", "Azure Backup Center", "Azure Resource Manager", "Azure Monitor"],
        "new_roles": ["Storage Blob Data Reader", "Key Vault Secrets User", "Backup Contributor", "Contributor"],
        "network_shift_pct": 0.40,
        "risk_boost": 44,
    },
    {
        "after_month": 6,   # Mar 2026 — agent detection run date
        "off_hours_pct": 0.34,
        "new_countries": [("Germany", "Frankfurt"), ("Netherlands", "Amsterdam"), ("Ukraine", "Kyiv")],
        "new_apps": ["Azure Storage Explorer", "Azure Key Vault", "Azure Backup Center", "Azure Resource Manager", "Azure Monitor"],
        "new_roles": ["Storage Blob Data Reader", "Key Vault Secrets User", "Backup Contributor", "Contributor"],
        "network_shift_pct": 0.42,
        "risk_boost": 48,
    },
]


def get_drift_phase(event_date: datetime) -> Optional[dict]:
    """Return the active drift phase for a given date, or None if pre-inflection."""
    if event_date < INFLECTION_DATE:
        return None
    months_after = (event_date.year - INFLECTION_DATE.year) * 12 + (event_date.month - INFLECTION_DATE.month)
    phase_idx = min(months_after, len(DRIFT_PHASES) - 1)
    return DRIFT_PHASES[phase_idx]


def random_datetime_in_month(year: int, month: int, hour_range: tuple, off_hours_pct: float = 0.0) -> datetime:
    """Generate a random datetime within a given month."""
    import calendar
    last_day = calendar.monthrange(year, month)[1]
    day = random.randint(1, last_day)

    if random.random() < off_hours_pct:
        # Off-hours: 10pm–5am
        hour = random.choice(list(range(22, 24)) + list(range(0, 5)))
    else:
        hour = random.randint(hour_range[0], hour_range[1] - 1)

    minute  = random.randint(0, 59)
    second  = random.randint(0, 59)
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def generate_raw_events() -> list[dict]:
    """Generate all RobDentity_RawEvents_CL records."""
    records = []

    # Iterate month by month across the 12-month window
    current = BASELINE_START
    while current < END_DATE:
        year, month = current.year, current.month

        for upn, user in USERS.items():
            profile = BASELINE_PROFILES[upn]
            phase   = get_drift_phase(current) if user["scenario"] == "compromised" else None

            # Sam does legitimate international travel in month 8 (Nov 2025) — benign contrast
            sam_travel = (upn == "sam.lee@contoso.com" and
                          ((year == 2025 and month >= 11) or (year == 2026 and month <= 1)))

            for _ in range(EVENTS_PER_MONTH):
                off_hours_pct = phase["off_hours_pct"] if phase else 0.02
                event_dt = random_datetime_in_month(year, month, profile["hours"], off_hours_pct)

                # --- device selection ---
                device = random.choice(profile["devices"])
                if phase and phase.get("new_device") and random.random() < 0.35:
                    device = phase["new_device"]

                # --- geography ---
                country, city = profile["country"], profile["city"]
                if phase and phase.get("new_countries") and random.random() < 0.25:
                    country, city = random.choice(phase["new_countries"])
                if sam_travel and random.random() < 0.3:
                    country, city = "United Kingdom", "London"   # legitimate business trip

                # --- network ---
                network = profile["network"]
                if phase and random.random() < phase.get("network_shift_pct", 0):
                    network = "DatacenterIP"

                # --- apps ---
                app_pool = list(profile["apps"])
                if phase and phase.get("new_apps"):
                    app_pool += phase["new_apps"]
                app = random.choice(app_pool)

                # --- resources ---
                resource = random.choice(profile["resources"] + (["stg-prod-backup-01"] if phase else []))

                # --- roles held at time of session ---
                roles = list(profile["roles"])
                if phase and phase.get("new_roles"):
                    roles = list(set(roles + phase["new_roles"]))

                # --- auth ---
                auth_method = profile["auth_method"]
                mfa_result  = "Approved"
                if phase and random.random() < 0.08:
                    mfa_result = "Challenged"

                # --- data volume — exfil ramps up in late drift phases ---
                lo, hi = profile["data_volume_kb"]
                if phase and phase["after_month"] >= 4:
                    hi = hi * 4   # simulates backup/exfil activity
                data_kb = random.randint(lo, hi)

                # --- risk score ---
                base_lo, base_hi = profile["risk_score"]
                risk_score = round(random.uniform(base_lo, base_hi) + (phase["risk_boost"] if phase else 0), 1)
                risk_score = min(risk_score, 100.0)

                # --- event flag ---
                if risk_score < 25:
                    flag = "Normal"
                elif risk_score < 50:
                    flag = "Drift"
                elif risk_score < 75:
                    flag = "Suspicious"
                else:
                    flag = "Critical"

                records.append({
                    "TimeGenerated":         event_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "createdDateTime":       event_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "UserPrincipalName":     upn,
                    "UserId":                user["id"],
                    "EventType":             random.choice(["SignIn", "AppAccess", "AdminAction", "TokenRefresh"]),
                    "LoginGeo_Country":      country,
                    "LoginGeo_City":         city,
                    "IPAddress":             f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "AuthNetworkCategory":   network,
                    "DeviceId":              device["id"],
                    "DeviceTrustType":       device["trust"],
                    "DevicePlatform":        device["platform"],
                    "ApplicationAccessed":   app,
                    "ResourceAccessed":      resource,
                    "AuthMethod":            auth_method,
                    "MFAResult":             mfa_result,
                    "DataVolumeKB":          data_kb,
                    "SessionDurationSeconds": random.randint(60, 3600),
                    "RolesHeldAtTime":       json.dumps(roles),
                    "RobDentity_RiskScore":  risk_score,
                    "RobDentity_EventFlag":  flag,
                })

        # Advance one month
        if month == 12:
            current = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            current = datetime(year, month + 1, 1, tzinfo=timezone.utc)

    return records


def generate_findings() -> list[dict]:
    """
    Generate RobDentity_Findings_CL records.

    Key design: RobDentity's engine only operates on 30 days.
    It fires Low/Medium findings throughout the drift phase and 
    one Medium in Feb 2026 — the only one in the 30-day window.
    All findings have RobDentity_WindowUsed = "30d".

    The agent in Lab 4 reads 12 months of RawEvents and produces
    a Critical finding RobDentity's engine never could.
    """
    findings = []

    # RobDentity findings for alex.smith — visible within 30-day windows
    alex_findings = [
        # Oct 2025 — low, dismissed
        {
            "TimeGenerated":         "2025-10-14T09:00:00Z",
            "createdDateTime":       "2025-10-14T09:00:00Z",
            "UserPrincipalName":     "alex.smith@contoso.com",
            "FindingId":             "RD-2025-1041",
            "FindingType":           "NewGeographyDetected",
            "Severity":              "Low",
            "Description":           "Sign-in detected from Germany (Frankfurt). Single occurrence within 30-day window. No prior history available.",
            "TriggeredBy":           "geo_anomaly_detector",
            "RobDentity_WindowUsed": "30d",
            "Confidence":            0.41,
            "Disposition":           "Dismissed",
        },
        # Dec 2025 — medium, dismissed
        {
            "TimeGenerated":         "2025-12-03T10:15:00Z",
            "createdDateTime":       "2025-12-03T10:15:00Z",
            "UserPrincipalName":     "alex.smith@contoso.com",
            "FindingId":             "RD-2025-1187",
            "FindingType":           "OffHoursLoginPattern",
            "Severity":              "Medium",
            "Description":           "Elevated off-hours login frequency observed in last 30 days. Insufficient history to establish baseline deviation.",
            "TriggeredBy":           "session_timing_detector",
            "RobDentity_WindowUsed": "30d",
            "Confidence":            0.55,
            "Disposition":           "Dismissed",
        },
        # Feb 2026 — medium, open — this is the ONE finding in the 30-day window when the agent runs
        {
            "TimeGenerated":         "2026-02-18T08:30:00Z",
            "createdDateTime":       "2026-02-18T08:30:00Z",
            "UserPrincipalName":     "alex.smith@contoso.com",
            "FindingId":             "RD-2026-0218",
            "FindingType":           "OffHoursLoginPattern",
            "Severity":              "Medium",
            "Description":           "Repeated off-hours sign-ins detected from non-CorporateVPN networks in last 30 days. Risk score elevated. Recommend review.",
            "TriggeredBy":           "session_timing_detector",
            "RobDentity_WindowUsed": "30d",
            "Confidence":            0.61,
            "Disposition":           "Open",
        },
    ]

    # Normal users each have zero findings — intentionally no findings for sam/priya to keep noise low
    findings.extend(alex_findings)
    return findings


def chunk(lst: list, size: int):
    """Split a list into chunks of given size."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def ingest(client: LogsIngestionClient, dcr_id: str, stream: str, records: list[dict]):
    """Send records to Sentinel in batches of 500."""
    total = 0
    for batch in chunk(records, 500):
        client.upload(rule_id=dcr_id, stream_name=stream, logs=batch)
        total += len(batch)
        print(f"  ✓ Sent {total}/{len(records)} records to {stream}")


def main():
    print("=" * 70)
    print("RobDentity Synthetic Data Generator")
    print("Generating 12 months of identity telemetry (Mar 2025 – Mar 2026)")
    print("=" * 70)

    # Authenticate using current az CLI session
    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=DCE_ENDPOINT, credential=credential)

    # Generate data
    print("\n[1/2] Generating RobDentity_RawEvents_CL ...")
    raw_events = generate_raw_events()
    print(f"      Generated {len(raw_events)} raw event records across 3 users")

    print("\n[2/2] Generating RobDentity_Findings_CL ...")
    findings = generate_findings()
    print(f"      Generated {len(findings)} findings records")

    # Ingest
    print("\nIngesting RobDentity_RawEvents_CL ...")
    ingest(client, DCR_IMMUTABLE_ID, RAW_EVENTS_STREAM, raw_events)

    print("\nIngesting RobDentity_Findings_CL ...")
    ingest(client, DCR_IMMUTABLE_ID, FINDINGS_STREAM, findings)

    print("\n" + "=" * 70)
    print("✓ Ingestion complete.")
    print("  Note: Data may take 5–20 minutes to appear in Sentinel.")
    print()
    print("  To verify in Sentinel Data Lake Exploration:")
    print("  RobDentity_RawEvents_CL | summarize count() by UserPrincipalName")
    print("  RobDentity_Findings_CL  | project createdDateTime, UserPrincipalName, Severity, Disposition")
    print("=" * 70)


if __name__ == "__main__":
    main()
