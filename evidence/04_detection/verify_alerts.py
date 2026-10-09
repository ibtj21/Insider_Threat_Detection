from opensearchpy import OpenSearch, helpers
from collections import defaultdict

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False
)

SOURCE_INDEX = "access-logs"
ALERTS_INDEX = "alerts"

print("Loading ground truth (is_suspicious) from access-logs...")
truth_by_event = {}
for doc in helpers.scan(client, index=SOURCE_INDEX, query={"query": {"match_all": {}}}, size=1000):
    src = doc["_source"]
    truth_by_event[src["event_id"]] = {
        "is_suspicious": src["is_suspicious"],
        "employee_id": src["employee_id"]
    }
print(f"Loaded {len(truth_by_event)} ground-truth records")

print("Loading alerts from alerts index...")
alerts = list(helpers.scan(client, index=ALERTS_INDEX, query={"query": {"match_all": {}}}, size=1000))
print(f"Loaded {len(alerts)} alerts")

true_positives = []   # alert fired AND is_suspicious == 1
false_positives = []  # alert fired but is_suspicious == 0

for a in alerts:
    src = a["_source"]
    event_id = src["event_id"]
    truth = truth_by_event.get(event_id)
    if truth is None:
        continue
    if truth["is_suspicious"] == 1:
        true_positives.append(src)
    else:
        false_positives.append(src)

print()
print("===== RESULTS =====")
print(f"Total alerts: {len(alerts)}")
print(f"True positives (correctly matched planted-suspicious events): {len(true_positives)}")
print(f"False positives (flagged, but NOT planted as suspicious): {len(false_positives)}")

# How many planted-suspicious events were MISSED entirely (no alert generated)?
suspicious_event_ids = {eid for eid, t in truth_by_event.items() if t["is_suspicious"] == 1}
alerted_event_ids = {a["_source"]["event_id"] for a in alerts}
missed = suspicious_event_ids - alerted_event_ids

print(f"Planted-suspicious events total: {len(suspicious_event_ids)}")
print(f"Planted-suspicious events MISSED (no alert fired): {len(missed)}")

# Break down false positives by reason and employee, so we know exactly why they happened
print()
print("===== FALSE POSITIVE BREAKDOWN (why these fired) =====")
reason_counts = defaultdict(int)
employee_counts = defaultdict(int)
for fp in false_positives:
    for reason in fp["reasons"]:
        reason_counts[reason] += 1
    employee_counts[fp["employee_id"]] += 1

print("By reason:")
for reason, cnt in reason_counts.items():
    print(f"  {reason}: {cnt}")

print("By employee (top 10):")
for emp, cnt in sorted(employee_counts.items(), key=lambda x: -x[1])[:10]:
    print(f"  {emp}: {cnt} false positive alert(s)")

# Show a few actual false positive records so you can see the raw evidence
print()
print("===== SAMPLE FALSE POSITIVE RECORDS =====")
for fp in false_positives[:5]:
    print(fp)
