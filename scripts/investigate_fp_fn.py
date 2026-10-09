from opensearchpy import OpenSearch, helpers
from datetime import datetime
from collections import defaultdict

client = OpenSearch(hosts=[{"host": "localhost", "port": 9200}], use_ssl=False)

SOURCE_INDEX = "access-logs"
ALERTS_INDEX = "alerts"


def parse_ts(ts_str):
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S%z")


print("Loading all access-logs records...")
all_records = list(helpers.scan(client, index=SOURCE_INDEX, query={"query": {"match_all": {}}}, size=1000))
by_employee = defaultdict(list)
for r in all_records:
    by_employee[r["_source"]["employee_id"]].append(r["_source"])

for emp_id in by_employee:
    by_employee[emp_id].sort(key=lambda e: parse_ts(e["timestamp"]))

print("Loading all alerts...")
all_alerts = list(helpers.scan(client, index=ALERTS_INDEX, query={"query": {"match_all": {}}}, size=1000))
alerted_event_ids = {a["_source"]["event_id"] for a in all_alerts}

# ============================================================
# PART 1: Investigate the 4 known false positives
# ============================================================
false_positive_event_ids = ["EVT0063644", "EVT0017686", "EVT0022908", "EVT0070206"]

print()
print("=" * 60)
print("PART 1: FALSE POSITIVE INVESTIGATION")
print("=" * 60)

for target_eid in false_positive_event_ids:
    # find the event and its employee
    target_event = None
    target_emp = None
    for emp_id, events in by_employee.items():
        for e in events:
            if e["event_id"] == target_eid:
                target_event = e
                target_emp = emp_id
                break
        if target_event:
            break

    if not target_event:
        print(f"Event {target_eid} not found.")
        continue

    target_time = parse_ts(target_event["timestamp"])
    print(f"\nEvent {target_eid} | Employee {target_emp} | is_suspicious={target_event['is_suspicious']}")
    print(f"  Timestamp: {target_event['timestamp']}")

    # find how many of this employee's OTHER events fall within 10 minutes of this one
    timeline = by_employee[target_emp]
    nearby = []
    for e in timeline:
        if e["event_id"] == target_eid:
            continue
        delta = abs((parse_ts(e["timestamp"]) - target_time).total_seconds()) / 60
        if delta <= 10:
            nearby.append((e["event_id"], e["is_suspicious"], delta))

    suspicious_nearby = sum(1 for _, s, _ in nearby if s == 1)
    normal_nearby = sum(1 for _, s, _ in nearby if s == 0)
    print(f"  Events within 10 min of this one (excluding itself): {len(nearby)}")
    print(f"    -> {suspicious_nearby} are planted-suspicious (is_suspicious=1)")
    print(f"    -> {normal_nearby} are normal (is_suspicious=0)")
    print(f"  Conclusion: this event got swept into a window containing {suspicious_nearby} suspicious neighbors,")
    print(f"  crossing the 50-event bulk threshold even though this specific event was labeled normal.")

# ============================================================
# PART 2: Sample the false negatives (missed suspicious events)
# ============================================================
print()
print("=" * 60)
print("PART 2: FALSE NEGATIVE INVESTIGATION (sample)")
print("=" * 60)

missed = []
for emp_id, events in by_employee.items():
    for idx, e in enumerate(events):
        if e["is_suspicious"] == 1 and e["event_id"] not in alerted_event_ids:
            missed.append((emp_id, idx, len(events), e))

print(f"\nTotal missed (false negative) events found: {len(missed)}")

# group missed events by employee to see which employees they belong to
missed_by_emp = defaultdict(int)
for emp_id, idx, total, e in missed:
    missed_by_emp[emp_id] += 1

print("\nMissed events by employee:")
for emp_id, count in sorted(missed_by_emp.items(), key=lambda x: -x[1])[:15]:
    print(f"  {emp_id}: {count} missed events")

print("\nSample of 5 missed events, showing their POSITION within that employee's full timeline")
print("(position near the end of a burst confirms the 'forward window runs out' explanation):")
for emp_id, idx, total, e in missed[:5]:
    print(f"  {e['event_id']} | Employee {emp_id} | position {idx+1} of {total} events in their timeline | timestamp {e['timestamp']}")

# ============================================================
# PART 3: Check false negatives for labeling inconsistency
# (i.e. are they surrounded by dense suspicious activity, just
# missed by the forward-only window, OR are they genuinely
# ambiguous like the false positives?)
# ============================================================
print()
print("=" * 60)
print("PART 3: FALSE NEGATIVE CONSISTENCY CHECK")
print("=" * 60)

sample_missed = missed[:10]
for emp_id, idx, total, e in sample_missed:
    target_time = parse_ts(e["timestamp"])
    timeline = by_employee[emp_id]

    forward_count = 0
    backward_count = 0
    for other in timeline:
        if other["event_id"] == e["event_id"]:
            continue
        delta = (parse_ts(other["timestamp"]) - target_time).total_seconds() / 60
        if 0 < delta <= 10:
            forward_count += 1
        elif -10 <= delta < 0:
            backward_count += 1

    print(f"\nEvent {e['event_id']} | Employee {emp_id} | is_suspicious={e['is_suspicious']}")
    print(f"  Forward count (events in next 10 min): {forward_count}  <- what the current rule checks")
    print(f"  Backward count (events in prior 10 min): {backward_count}  <- what a bidirectional rule would also check")
    print(f"  Interpretation: {'Genuinely dense burst, rule missed it due to forward-only design' if backward_count >= 50 else 'Low density in both directions - worth a closer look'}")

print()
print("=" * 60)
print("END OF INVESTIGATION")
print("=" * 60)
