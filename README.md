# Sentinel Lab 03 — Impossible Travel Investigation

## Overview

This lab documents a Microsoft Sentinel investigation focused on identifying a possible impossible-travel authentication pattern.

The investigation examines successful authentication events for multiple synthetic users and compares their sign-in locations, source IP addresses, timestamps, and application context.

The primary investigation focuses on `user1@sentinellab.local`, who successfully authenticated from Hyderabad and then New York only 30 minutes later.

The investigation uses synthetic authentication data created with KQL `datatable()`. The events are not presented as real Microsoft Entra ID `SigninLogs` telemetry.

## Investigation Scenario

A SOC analyst identifies an account that appears to authenticate successfully from geographically different locations within a very short period.

The primary activity is:

- User: `user1@sentinellab.local`
- First location: Hyderabad
- First IP: `10.10.10.25`
- First authentication: `2026-09-13 10:00 UTC`
- Second location: New York
- Second IP: `203.0.113.25`
- Second authentication: `2026-09-13 10:30 UTC`
- Time difference: 30 minutes
- Application: Microsoft Office

The pattern is consistent with a possible impossible-travel anomaly and requires further investigation.

## Lab Objectives

- Understand the concept of impossible travel.
- Analyze successful authentication events.
- Identify users authenticating from multiple locations.
- Compare authentication timestamps.
- Calculate the time difference between sign-ins.
- Identify possible impossible-travel patterns.
- Examine source IP addresses and application context.
- Distinguish an authentication anomaly from confirmed account compromise.
- Evaluate false-positive explanations.
- Document evidence limitations.
- Map the investigation to MITRE ATT&CK.

## Environment

- Microsoft Sentinel
- Azure Portal
- Workspace: `Microsoft-Sentinel-Workspace`
- Kusto Query Language (KQL)
- Synthetic authentication dataset
- KQL `datatable()`
- Microsoft Office as the synthetic application context

## Data Source

The investigation uses an inline KQL `datatable()` rather than a persistent Sentinel table.

The synthetic dataset contains:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `ResultType`
- `AppDisplayName`
- `Location`

All events in the primary investigation have `ResultType == 0`, representing successful authentication within the synthetic dataset.

## Synthetic Dataset

```kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-13T10:00:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Microsoft Office", "Hyderabad",
    datetime(2026-09-13T10:30:00Z), "user1@sentinellab.local", "203.0.113.25", 0, "Microsoft Office", "New York",
    datetime(2026-09-13T11:00:00Z), "user2@sentinellab.local", "10.10.10.30", 0, "Microsoft Office", "Hyderabad",
    datetime(2026-09-13T17:00:00Z), "user2@sentinellab.local", "10.10.10.31", 0, "Microsoft Office", "Hyderabad",
    datetime(2026-09-13T11:00:00Z), "user3@sentinellab.local", "10.10.10.40", 0, "Microsoft Office", "Mumbai",
    datetime(2026-09-13T11:10:00Z), "user3@sentinellab.local", "10.10.10.41", 0, "Microsoft Office", "Pune"
]
| order by UserPrincipalName asc, TimeGenerated asc
```

## Investigation Workflow

The investigation followed this sequence:

1. Verified that KQL `datatable()` execution worked.
2. Loaded the synthetic authentication dataset.
3. Reviewed successful sign-in events.
4. Compared the number of locations used by each user.
5. Compared sequential sign-in timestamps.
6. Calculated the time difference between authentication events.
7. Identified different-location sign-ins occurring within 60 minutes.
8. Investigated source IP addresses.
9. Reviewed application context.
10. Evaluated possible explanations.
11. Assigned a SOC investigation verdict.

## Initial Authentication Review

The initial dataset contained six successful authentication events involving three synthetic users.

### user1

- 10:00 UTC — Hyderabad
- 10:30 UTC — New York

### user2

- 11:00 UTC — Hyderabad
- 17:00 UTC — Hyderabad

### user3

- 11:00 UTC — Mumbai
- 11:10 UTC — Pune

## Location Analysis

The investigation used `dcount()` and `make_set()` to identify users with multiple authentication locations.

```kusto
| where ResultType == 0
| summarize
    LocationCount=dcount(Location),
    Locations=make_set(Location)
    by UserPrincipalName
| order by LocationCount desc
```

Observed results:

- `user1` — 2 locations: Hyderabad, New York
- `user3` — 2 locations: Mumbai, Pune
- `user2` — 1 location: Hyderabad

Multiple locations alone were not treated as malicious.

## Time-Based Analysis

Sequential successful sign-ins were compared using `prev()` after sorting and serializing the events.

The resulting comparisons were:

| User | Previous Location | Current Location | Time Difference |
|---|---|---|---:|
| user1 | Hyderabad | New York | 30 minutes |
| user2 | Hyderabad | Hyderabad | 360 minutes |
| user3 | Mumbai | Pune | 10 minutes |

The `user1` event was the strongest impossible-travel candidate because the locations were geographically distant and the authentication interval was only 30 minutes.

## Detection Logic

For this training lab, an impossible-travel candidate was defined as:

- Successful authentication
- Same user
- Different locations
- Less than 60 minutes between consecutive sign-ins

The detection logic was:

```kusto
| where UserPrincipalName == PreviousUser
| extend MinutesBetween =
    datetime_diff('minute', TimeGenerated, PreviousTime)
| where Location != PreviousLocation
| where MinutesBetween < 60
| project
    UserPrincipalName,
    PreviousTime,
    TimeGenerated,
    PreviousLocation,
    Location,
    PreviousIP,
    IPAddress,
    MinutesBetween
```

The query identified:

- `user1`: Hyderabad → New York — 30 minutes
- `user3`: Mumbai → Pune — 10 minutes

The Mumbai-to-Pune result was retained as a comparison case because the synthetic dataset does not provide a numeric geographic distance.

## Primary Finding

The strongest investigation finding was:

```text
User:              user1@sentinellab.local
Previous location: Hyderabad
Previous IP:       10.10.10.25
Previous time:     10:00 UTC
Current location:  New York
Current IP:        203.0.113.25
Current time:      10:30 UTC
Time difference:   30 minutes
```

This creates a clear impossible-travel candidate.

## Investigation Verdict

**Suspicious — Possible Account Compromise**

The authentication pattern is suspicious and consistent with possible impossible-travel activity.

However, the available evidence does not prove account compromise.

The dataset does not contain:

- MFA information
- Conditional Access results
- Device information
- Sign-in risk
- Authentication method
- VPN information
- User-agent information
- Endpoint telemetry
- Post-authentication activity

Therefore, the appropriate SOC conclusion is to treat the activity as suspicious and requiring further investigation rather than confirmed compromise.

## False-Positive Considerations

Possible legitimate explanations include:

- VPN usage
- Proxy infrastructure
- Corporate network egress
- Mobile carrier routing
- Incorrect IP geolocation
- Legitimate travel
- Shared credentials
- Cloud-based authentication infrastructure

Impossible travel should therefore be treated as an investigation signal rather than automatic proof of malicious activity.

## MITRE ATT&CK

### T1078 — Valid Accounts

The investigation is most closely associated with valid-account abuse because an attacker using compromised credentials could generate successful authentication events from unexpected locations.

Impossible travel itself is an anomaly or detection pattern rather than a standalone MITRE ATT&CK technique.

## Evidence Limitations

This lab uses synthetic data.

The users, IP addresses, locations, and authentication events were created specifically for the investigation and do not represent real production activity.

The dataset also does not provide enough telemetry to determine whether the credentials were actually compromised.

## Key SOC Lesson

**An anomaly is an investigation starting point, not automatically a confirmed incident.**

The analyst should follow the evidence, validate available telemetry, investigate alternative explanations, and clearly document what is confirmed, plausible, and unknown.

## Lab Outcome

This lab demonstrates:

- Authentication investigation
- KQL filtering
- `dcount()`
- `make_set()`
- `prev()`
- `serialize`
- `datetime_diff()`
- Sequential event analysis
- Location-based anomaly detection
- Source IP investigation
- Evidence-based SOC verdicts
- False-positive analysis
- MITRE ATT&CK mapping

## Evidence Summary

| Evidence | Finding |
|---|---|
| User | `user1@sentinellab.local` |
| First location | Hyderabad |
| Second location | New York |
| Time difference | 30 minutes |
| First IP | `10.10.10.25` |
| Second IP | `203.0.113.25` |
| Application | Microsoft Office |
| Authentication result | Successful |
| Assessment | Suspicious |
| Confidence | Moderate |
| Compromise confirmed | No |
| Primary limitation | Synthetic telemetry |

## Conclusion

The investigation identified a suspicious authentication pattern for `user1@sentinellab.local`, where successful authentication occurred from Hyderabad and New York only 30 minutes apart. This is consistent with an impossible-travel anomaly and warrants additional investigation. Because the dataset does not include MFA, device, risk, VPN, endpoint, or post-authentication telemetry, the investigation cannot confirm account compromise.
