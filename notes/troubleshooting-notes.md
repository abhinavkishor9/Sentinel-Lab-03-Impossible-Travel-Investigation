# Sentinel Lab 03 — Troubleshooting Notes

## Overview

This document records the technical issues encountered while building and executing Sentinel Lab 03.

The purpose is to document the actual troubleshooting process rather than hide the limitations encountered during the lab.

## Issue 1 — Microsoft Entra Sign-In Telemetry Was Not Available

### Problem

The original investigation concept was based on Microsoft Entra `SigninLogs`.

The workspace did not provide usable `SigninLogs` telemetry for the investigation.

Earlier attempts to query sign-in fields such as:

```text
TimeGenerated
Timestamp
```

resulted in schema-related errors because the expected sign-in telemetry was not available in the workspace.

### Impact

A production-style investigation using:

```kusto
SigninLogs
```

could not be completed using actual workspace authentication events.

### Resolution

The lab was redesigned to use synthetic authentication data through KQL `datatable()`.

This allowed the investigation to continue without fabricating real Sentinel telemetry.

### Documentation Decision

The README and investigation notes explicitly identify the data as synthetic.

The lab does not claim that the events originated from Microsoft Entra ID.

---

## Issue 2 — `datatable()` Was Used Instead of a Persistent Table

### Problem

The workspace did not have the required persistent authentication dataset for the investigation.

A persistent custom table would require additional ingestion configuration.

### Resolution

The investigation uses KQL `datatable()`.

The working structure is:

```kusto
datatable(
    Column1:type,
    Column2:type
)
[
    ...
]
| where ...
| summarize ...
```

This keeps the lab focused on KQL investigation and detection logic.

### Important Limitation

The `datatable()` dataset is defined inside the query itself.

It should not be treated as a permanent Sentinel table.

Microsoft documents `datatable()` as an operator that creates a table whose schema and values are defined directly in the query.

---

## Issue 3 — `let AuthData` Produced an Error

### Error

An earlier version attempted to define the dataset using:

```kusto
let AuthData = datatable(...);
```

The query returned:

```text
No tabular expression statement found
```

### Cause

The query ended after the `let` statement without returning a tabular expression.

A `let` statement defines a variable. It does not by itself produce the final tabular result.

### Resolution

The lab was changed to use `datatable()` directly as the query's tabular expression.

Instead of:

```kusto
let AuthData = datatable(...);
```

the working pattern became:

```kusto
datatable(...)
[
    ...
]
| where ...
```

### Result

The revised query executed successfully and returned the expected authentication events.

### Lesson

If a `let` statement is used, it must be followed by a final query expression that uses the defined variable.

For example:

```kusto
let AuthData = datatable(
    User:string
)
[
    "user1"
];

AuthData
| project User
```

For this lab, however, direct `datatable()` queries were simpler and less error-prone.

---

## Issue 4 — Each Query Needs the Dataset Definition

### Problem

Because the lab uses inline synthetic data, the dataset is not available as a persistent table between independent query executions.

### Resolution

Each investigation query contains the complete `datatable()` definition.

For example:

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
    ...
]
| where ResultType == 0
```

### Lesson

The dataset definition must be repeated when running a separate query.

This makes the queries longer but keeps the lab reproducible.

---

## Issue 5 — Multiple Locations Do Not Automatically Mean Impossible Travel

### Observation

The dataset showed:

```text
user1 → Hyderabad, New York
user3 → Mumbai, Pune
```

Both users authenticated from multiple locations.

### Investigation Adjustment

The investigation did not classify multiple locations alone as suspicious.

Instead, it compared:

- Previous location
- Current location
- Previous timestamp
- Current timestamp
- Time difference
- Source IP

### Result

The strongest candidate was:

```text
user1
Hyderabad → New York
30 minutes
```

The Mumbai-to-Pune event was retained as a comparison case.

---

## Issue 6 — Sequential Analysis Required Sorting and Serialization

### Problem

To compare the current authentication event with the previous authentication event for the same user, the dataset needed to be ordered correctly.

### Resolution

The investigation used:

```kusto
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
```

Then:

```kusto
| extend
    PreviousUser = prev(UserPrincipalName),
    PreviousTime = prev(TimeGenerated),
    PreviousLocation = prev(Location),
    PreviousIP = prev(IPAddress)
```

The query then restricted the comparison to the same user:

```kusto
| where UserPrincipalName == PreviousUser
```

### Result

The investigation successfully calculated sequential authentication intervals.

---

## Issue 7 — Time Difference Calculation

### Problem

The investigation required calculating the time between consecutive successful authentication events.

### Resolution

The query used:

```kusto
| extend MinutesBetween =
    datetime_diff('minute', TimeGenerated, PreviousTime)
```

### Results

The dataset produced:

```text
user1 → 30 minutes
user2 → 360 minutes
user3 → 10 minutes
```

The `user1` event was the primary impossible-travel candidate.

---

## Issue 8 — Impossible Travel Threshold

### Lab Threshold

The lab used:

```text
MinutesBetween < 60
```

along with:

```text
Location != PreviousLocation
```

### Important Limitation

The 60-minute threshold is a training threshold.

It is not a universal production impossible-travel threshold.

Real-world analysis should consider:

- Actual geographic distance
- Estimated travel time
- VPN usage
- Proxy infrastructure
- Corporate egress
- IP geolocation accuracy
- Historical user behavior
- Device identity
- Authentication method
- Sign-in risk

Microsoft's security documentation also notes that impossible-travel detections can generate false positives, including VPN-related location differences.

---

## Issue 9 — IP Addresses Were Not Classified as Malicious

The dataset contains:

```text
10.10.10.25
203.0.113.25
```

These addresses are part of the synthetic lab dataset.

They were not treated as confirmed malicious infrastructure.

No external reputation or threat-intelligence conclusion was made from these values.

---

## Issue 10 — Impossible Travel Does Not Prove Account Compromise

### Problem

The Hyderabad-to-New York pattern could easily be described as a confirmed account takeover.

That conclusion is not supported by the available evidence.

### Resolution

The final verdict was documented as:

```text
Suspicious — Possible Account Compromise
```

rather than:

```text
Confirmed Account Compromise
```

### Reason

The dataset does not contain:

- MFA
- Conditional Access
- Device information
- Sign-in risk
- Authentication method
- VPN information
- Endpoint activity
- Post-authentication activity

Therefore, the investigation identifies an anomaly but cannot establish compromise.

---

## Issue 11 — No Persistent Analytics Rule

### Decision

A Sentinel Analytics Rule was not created for the synthetic dataset.

### Reason

The current lab uses temporary inline `datatable()` telemetry rather than persistent workspace data.

The purpose of this lab is to demonstrate:

- KQL
- Authentication analysis
- Location comparison
- Time-based correlation
- Investigation reasoning
- Evidence-based verdicts

A scheduled analytics rule should be built against persistent telemetry rather than pretending that the synthetic events are continuously available workspace data.

### Future Enhancement

If persistent authentication telemetry becomes available, the detection logic can be adapted into a Sentinel Analytics Rule.

---

## Final Troubleshooting Outcome

The lab was successfully completed after making the following changes:

1. Avoided unavailable `SigninLogs`.
2. Used synthetic authentication data with `datatable()`.
3. Used direct `datatable()` queries instead of relying on a temporary `let` variable.
4. Repeated the dataset definition for each independent query.
5. Used `sort`, `serialize`, and `prev()` for sequential authentication analysis.
6. Used `datetime_diff()` to calculate authentication intervals.
7. Treated location anomalies as investigation signals rather than proof of compromise.
8. Documented synthetic data and evidence limitations.
9. Avoided creating a misleading Analytics Rule against temporary data.

## Final Technical Outcome

The investigation successfully identified:

```text
user1
Hyderabad
10:00 UTC
        ↓
30 minutes
        ↓
New York
10:30 UTC
```

The resulting assessment was:

**Suspicious — Possible Account Compromise**
