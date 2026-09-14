# Sentinel Lab 03 — Timeline

## Investigation Timeline

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| 09:00 | KQL validation | Basic `datatable()` query executed successfully | Synthetic data approach confirmed |
| 09:05 | Dataset loaded | Six synthetic successful authentication events | Dataset available for analysis |
| 09:10 | Authentication review | Successful sign-in events reviewed | Six events identified |
| 09:15 | Location analysis | `dcount()` and `make_set()` used | user1 and user3 used multiple locations |
| 09:20 | Sequential analysis | `prev()` used after sorting and serialization | Previous authentication identified |
| 09:25 | Time correlation | `datetime_diff()` calculated | user1: 30 min, user2: 360 min, user3: 10 min |
| 09:30 | Location correlation | Different-location events filtered | user1 and user3 identified as candidates |
| 09:35 | Primary finding | Hyderabad → New York for user1 | 30-minute location change identified |
| 09:40 | Source IP review | `10.10.10.25` → `203.0.113.25` | Source IP changed |
| 09:45 | Application review | Microsoft Office observed in both events | Consistent application context |
| 09:50 | Evidence assessment | Available and missing telemetry reviewed | Account compromise not confirmed |
| 09:55 | False-positive review | VPN, proxy, geolocation and travel considered | Alternative explanations remain possible |
| 10:00 | Final verdict | Evidence-based assessment completed | Suspicious — Possible Account Compromise |

## Primary Authentication Sequence

```text
10:00 UTC
user1@sentinellab.local
Hyderabad
10.10.10.25
Successful authentication
        |
        | 30 minutes
        v
10:30 UTC
user1@sentinellab.local
New York
203.0.113.25
Successful authentication
```

## Investigation Milestones

### Milestone 1 — Telemetry Validation

Confirmed that synthetic authentication data could be queried through KQL `datatable()`.

### Milestone 2 — Dataset Review

Loaded and reviewed six synthetic successful authentication events.

### Milestone 3 — Location Analysis

Identified users with multiple authentication locations.

Results:

```text
user1 → Hyderabad, New York
user2 → Hyderabad
user3 → Mumbai, Pune
```

### Milestone 4 — Sequential Analysis

Sorted the events by user and time and used `prev()` to identify the previous authentication event for each user.

### Milestone 5 — Time Correlation

Calculated the time between consecutive authentication events.

Results:

```text
user1 → 30 minutes
user2 → 360 minutes
user3 → 10 minutes
```

### Milestone 6 — Impossible Travel Candidate

Identified:

```text
user1
Hyderabad → New York
30 minutes
```

as the strongest impossible-travel candidate.

### Milestone 7 — Source IP Review

The primary authentication sequence involved:

```text
10.10.10.25
203.0.113.25
```

The IP addresses were treated as synthetic investigation fields and were not classified as malicious.

### Milestone 8 — Application Context

Both primary authentication events used:

```text
Microsoft Office
```

### Milestone 9 — Evidence Assessment

Confirmed that the authentication pattern was suspicious but that the available telemetry was insufficient to prove account compromise.

### Milestone 10 — Final Verdict

Assigned:

**Suspicious — Possible Account Compromise**

## Event Comparison

| User | Previous Location | Current Location | Time Difference | Assessment |
|---|---|---|---:|---|
| user1@sentinellab.local | Hyderabad | New York | 30 minutes | Primary impossible-travel candidate |
| user2@sentinellab.local | Hyderabad | Hyderabad | 360 minutes | No location change |
| user3@sentinellab.local | Mumbai | Pune | 10 minutes | Different-location candidate requiring context |

## Confirmed Evidence

- `user1` successfully authenticated from Hyderabad.
- `user1` successfully authenticated from New York.
- The two events were 30 minutes apart.
- The source IP changed.
- Both events used Microsoft Office.
- The dataset represents successful authentication events.

## Plausible Explanations

- Credential misuse
- VPN usage
- Proxy infrastructure
- Corporate network routing
- Incorrect IP geolocation
- Legitimate travel
- Shared credentials
- Cloud-based authentication infrastructure

## Unknown Information

- MFA status
- Conditional Access result
- Device identity
- Device compliance
- Sign-in risk
- Authentication method
- VPN usage
- IP geolocation accuracy
- Endpoint activity
- Post-authentication activity
- Whether credentials were actually compromised

## Technical Timeline

The main KQL techniques used during the investigation were:

```text
datatable()
where
project
summarize
dcount()
make_set()
sort
serialize
prev()
extend
datetime_diff()
order by
```

## Troubleshooting Milestones

### Issue — `SigninLogs` Unavailable

The expected Microsoft Entra sign-in telemetry was not available in the current workspace.

### Resolution

The lab was redesigned around synthetic KQL `datatable()` telemetry.

### Issue — `let AuthData` Error

An earlier query ended after the `let AuthData = datatable(...)` definition and produced:

```text
No tabular expression statement found
```

### Resolution

The lab switched to direct `datatable()` queries that return a tabular result.

### Issue — Temporary Dataset

The synthetic dataset is not persistent across independent queries.

### Resolution

Each investigation query includes the complete dataset definition.

## Final Investigation Outcome

The investigation successfully identified a possible impossible-travel pattern involving:

```text
user1@sentinellab.local

Hyderabad
10:00 UTC
        ↓
30 minutes
        ↓
New York
10:30 UTC
```

The activity was classified as:

**Suspicious — Possible Account Compromise**

The evidence does not support a confirmed account-compromise conclusion because supporting authentication, device, risk, VPN, and endpoint telemetry was unavailable.

## Final SOC Assessment

**Suspicious — Possible Account Compromise**

The investigation should be escalated for additional authentication and endpoint validation if equivalent activity were observed in real production telemetry.
