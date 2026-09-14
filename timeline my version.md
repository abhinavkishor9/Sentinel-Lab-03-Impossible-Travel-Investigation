# Timeline

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

