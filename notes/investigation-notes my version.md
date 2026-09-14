# Sentinel Lab 03 — Investigation Notes

## Evidence Reviewed

The synthetic dataset contained:

- `UserPrincipalName`
- `TimeGenerated`
- `IPAddress`
- `ResultType`
- `AppDisplayName`
- `Location`

All events used in the primary investigation had:

```text
ResultType == 0
```

This represents successful authentication within the synthetic dataset.

## Initial Dataset Review

The dataset contained six successful authentication events involving three users.

### user1

- 10:00 UTC — Hyderabad
- 10:30 UTC — New York

### user2

- 11:00 UTC — Hyderabad
- 17:00 UTC — Hyderabad

### user3

- 11:00 UTC — Mumbai
- 11:10 UTC — Pune

## Location Diversity

The location analysis produced:

```text
user1 → 2 locations → Hyderabad, New York
user2 → 1 location  → Hyderabad
user3 → 2 locations → Mumbai, Pune
```

This showed that `user1` and `user3` had multiple locations.

Multiple locations were not immediately classified as suspicious because legitimate users can authenticate from different locations.

## Location Analysis Query

The following KQL was used:

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
| where ResultType == 0
| summarize
    LocationCount=dcount(Location),
    Locations=make_set(Location)
    by UserPrincipalName
| order by LocationCount desc
```

## Location Analysis Results

The query returned:

| UserPrincipalName | LocationCount | Locations |
|---|---:|---|
| user1@sentinellab.local | 2 | Hyderabad, New York |
| user3@sentinellab.local | 2 | Mumbai, Pune |
| user2@sentinellab.local | 1 | Hyderabad |

## Sequential Authentication Analysis

The investigation then compared consecutive successful sign-ins for each user.

The `prev()` function was used after sorting and serializing the data.

The relevant KQL logic was:

```kusto
| where ResultType == 0
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PreviousUser = prev(UserPrincipalName),
    PreviousTime = prev(TimeGenerated),
    PreviousLocation = prev(Location),
    PreviousIP = prev(IPAddress)
| where UserPrincipalName == PreviousUser
| extend MinutesBetween =
    datetime_diff('minute', TimeGenerated, PreviousTime)
```

## Sequential Analysis Results

The query produced:

| User | Previous Location | Current Location | Previous IP | Current IP | Minutes Between |
|---|---|---|---|---|---:|
| user1@sentinellab.local | Hyderabad | New York | 10.10.10.25 | 203.0.113.25 | 30 |
| user2@sentinellab.local | Hyderabad | Hyderabad | 10.10.10.30 | 10.10.10.31 | 360 |
| user3@sentinellab.local | Mumbai | Pune | 10.10.10.40 | 10.10.10.41 | 10 |

## Impossible-Travel Filtering

The investigation then applied:

- Same user
- Different locations
- Less than 60 minutes between successful authentications

The filtering logic was:

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

## Detection Results

The query returned two candidates:

| User | Previous Location | Current Location | Time Difference |
|---|---|---|---:|
| user1@sentinellab.local | Hyderabad | New York | 30 minutes |
| user3@sentinellab.local | Mumbai | Pune | 10 minutes |

The `user1` event was considered the primary finding because the locations represent a clearly distant geographic transition.

The `user3` event was retained as a comparison case because the synthetic dataset does not provide geographic distance or travel-time information.

## Primary Finding

The strongest finding was:

```text
user1@sentinellab.local

10:00 UTC
Hyderabad
10.10.10.25
Successful authentication

        ↓ 30 minutes

10:30 UTC
New York
203.0.113.25
Successful authentication
```

The combination of different locations and a 30-minute interval creates a strong impossible-travel candidate.

## Source IP Analysis

The primary user authenticated from:

```text
10.10.10.25
203.0.113.25
```

The IP addresses were used as investigation fields.

The synthetic dataset does not contain:

- IP reputation
- ASN information
- VPN classification
- Proxy classification
- Threat intelligence
- Historical IP reputation

Therefore, neither IP was classified as malicious.

## Application Context

Both primary authentication events used:

```text
Microsoft Office
```

The consistent application context supports the authentication correlation but does not independently indicate malicious activity.

## Investigation Verdict

**Suspicious — Possible Account Compromise**

The authentication pattern is suspicious and consistent with possible impossible-travel activity.

The available evidence does not prove that the account was compromised.

## Confirmed Evidence

The following findings are directly supported by the synthetic dataset:

- `user1` authenticated successfully from Hyderabad.
- `user1` authenticated successfully from New York.
- The events occurred 30 minutes apart.
- The source IP changed.
- Both events used Microsoft Office.
- Both authentication events were successful.

## Plausible Explanations

The activity could potentially be explained by:

- Credential misuse
- VPN usage
- Proxy infrastructure
- Corporate network routing
- Incorrect IP geolocation
- Legitimate travel
- Shared credentials
- Cloud-based authentication infrastructure

## Unknown Information

The investigation cannot determine:

- Whether MFA was completed.
- Whether Conditional Access was applied.
- Whether the same device was used.
- Whether the device was compliant.
- Whether the sign-in was considered risky.
- Whether a VPN was being used.
- Whether IP geolocation was accurate.
- Whether endpoint activity occurred after authentication.
- Whether credentials were actually compromised.

