from opensearchpy import OpenSearch, helpers
from datetime import datetime
from collections import defaultdict

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False
)

SOURCE_INDEX = "access-logs"
ALERTS_INDEX = "alerts"

# ---- Detection thresholds (tune these, and note them in your report) ----
BUSINESS_START_HOUR = 8       # 8am
BUSINESS_END_HOUR = 18        # 6pm
BULK_WINDOW_MINUTES = 10      # look at events within this rolling window
BULK_THRESHOLD = 50           # this many events inside the window = bulk/volume anomaly
# ---------------------------------------------------------------------

# Recreate the alerts index fresh each run
if client.indices.exists(index=ALERTS_INDEX):
    client.indices.delete(index=ALERTS_INDEX)

alert_mapping = {
    "mappings": {
        "properties": {
            "alert_id": {"type": "keyword"},
            "employee_id": {"type": "keyword"},
            "event_id": {"type": "keyword"},
            "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ssZ"},
            "reasons": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "signal_count": {"type": "integer"}
        }
    }
}
client.indices.create(index=ALERTS_INDEX, body=alert_mapping)


def fetch_all_records():
    """Pull every document out of access-logs (handles more than 10,000 via scroll)."""
    query = {"query": {"match_all": {}}}
    return helpers.scan(client, index=SOURCE_INDEX, query=query, size=1000)


def parse_ts(ts_str):
    # format written by the loader: yyyy-MM-dd HH:mm:ssZ, e.g. 2026-06-11 09:45:01+0300
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S%z")


print("Fetching records from OpenSearch...")
records = list(fetch_all_records())
print(f"Fetched {len(records)} records from '{SOURCE_INDEX}'")

# Group events by employee so bulk-volume detection can look at each employee's own timeline
by_employee = defaultdict(list)
for r in records:
    src = r["_source"]
    by_employee[src["employee_id"]].append(src)

alerts = []
alert_counter = 1

for emp_id, events in by_employee.items():
    events_sorted = sorted(events, key=lambda e: parse_ts(e["timestamp"]))
    timestamps = [parse_ts(e["timestamp"]) for e in events_sorted]

    # --- Signal: bulk volume (rolling window count per event) ---
    bulk_flags = [False] * len(events_sorted)
    for i in range(len(timestamps)):
        window_count = 1
        for j in range(i + 1, len(timestamps)):
            delta_minutes = (timestamps[j] - timestamps[i]).total_seconds() / 60
            if delta_minutes <= BULK_WINDOW_MINUTES:
                window_count += 1
            else:
                break
        if window_count >= BULK_THRESHOLD:
            bulk_flags[i] = True

    # --- Signals: off-hours + scope violation (per event) + combine severity ---
    for idx, ev in enumerate(events_sorted):
        reasons = []
        hour = timestamps[idx].hour

        if hour < BUSINESS_START_HOUR or hour >= BUSINESS_END_HOUR:
            reasons.append("off_hours_access")

        if ev["accessed_segment"] != ev["assigned_segment"]:
            reasons.append("scope_violation")

        if bulk_flags[idx]:
            reasons.append("bulk_volume")

        if reasons:
            signal_count = len(reasons)
            if signal_count == 1:
                severity = "low"
            elif signal_count == 2:
                severity = "medium"
            else:
                severity = "high"

            alerts.append({
                "_index": ALERTS_INDEX,
                "_source": {
                    "alert_id": f"ALERT{alert_counter:07d}",
                    "employee_id": emp_id,
                    "event_id": ev["event_id"],
                    "timestamp": ev["timestamp"],
                    "reasons": reasons,
                    "severity": severity,
                    "signal_count": signal_count
                }
            })
            alert_counter += 1

print(f"Total alerts to index: {len(alerts)}")

if alerts:
    success, failed = helpers.bulk(client, alerts, raise_on_error=False)
    client.indices.refresh(index=ALERTS_INDEX)
    print(f"Indexed alerts: {success}")
    print(f"Failed: {failed if isinstance(failed, int) else len(failed)}")

count = client.count(index=ALERTS_INDEX)["count"]
print(f"Total documents in alerts index: {count}")
