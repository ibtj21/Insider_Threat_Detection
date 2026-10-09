from opensearchpy import OpenSearch, helpers
from collections import Counter

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False
)

ALERTS_INDEX = "alerts"

# Known employee ranges from generate_data.py (fixed regardless of random values,
# since these are based on list position / employee_id, not randomized fields)
NORMAL_EMP = "EMP0100"          # outside all special groups -> should have 0 alerts
OFF_HOURS_EMP = "EMP0001"       # employees[:10]
BULK_EMP = "EMP0011"            # employees[10:20]
SCOPE_EMP = "EMP0021"           # employees[20:30]
MULTI_SIGNAL_EMP = "EMP0031"    # employees[30:35]


def get_alerts_for_employee(emp_id):
    query = {"query": {"term": {"employee_id": emp_id}}}
    return list(helpers.scan(client, index=ALERTS_INDEX, query=query, size=1000))


def print_result(test_name, passed, expected, actual):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {test_name}")
    print(f"    Expected: {expected}")
    print(f"    Actual:   {actual}")
    print()


print("=" * 60)
print("STEP 7 - SECURITY TESTING MATRIX")
print("=" * 60)
print()

# ---------------- TEST 1: Normal behavior -> no alert ----------------
alerts = get_alerts_for_employee(NORMAL_EMP)
passed = len(alerts) == 0
print_result(
    "Test 1: Normal behavior -> no alert",
    passed,
    f"0 alerts for {NORMAL_EMP} (normal employee, standard hours, correct segment)",
    f"{len(alerts)} alert(s) found for {NORMAL_EMP}"
)

# ---------------- TEST 2: Off-hours access -> alert fires ----------------
alerts = get_alerts_for_employee(OFF_HOURS_EMP)
off_hours_alerts = [a for a in alerts if "off_hours_access" in a["_source"]["reasons"]]
passed = len(off_hours_alerts) > 0
print_result(
    "Test 2: Off-hours access -> alert fires",
    passed,
    f"Alert(s) with reason 'off_hours_access' for {OFF_HOURS_EMP}",
    f"{len(off_hours_alerts)} off-hours alert(s) found out of {len(alerts)} total alerts for {OFF_HOURS_EMP}"
)

# ---------------- TEST 3: Bulk volume -> alert fires ----------------
alerts = get_alerts_for_employee(BULK_EMP)
bulk_alerts = [a for a in alerts if "bulk_volume" in a["_source"]["reasons"]]
passed = len(bulk_alerts) > 0
print_result(
    "Test 3: Bulk volume -> alert fires",
    passed,
    f"Alert(s) with reason 'bulk_volume' for {BULK_EMP}",
    f"{len(bulk_alerts)} bulk-volume alert(s) found out of {len(alerts)} total alerts for {BULK_EMP}"
)

# ---------------- TEST 4: Out-of-segment access -> alert fires ----------------
alerts = get_alerts_for_employee(SCOPE_EMP)
scope_alerts = [a for a in alerts if "scope_violation" in a["_source"]["reasons"]]
passed = len(scope_alerts) > 0
print_result(
    "Test 4: Out-of-segment access -> alert fires",
    passed,
    f"Alert(s) with reason 'scope_violation' for {SCOPE_EMP}",
    f"{len(scope_alerts)} scope-violation alert(s) found out of {len(alerts)} total alerts for {SCOPE_EMP}"
)

# ---------------- TEST 5: Multi-signal -> higher severity ----------------
alerts = get_alerts_for_employee(MULTI_SIGNAL_EMP)
severity_counts = Counter(a["_source"]["severity"] for a in alerts)
high_count = severity_counts.get("high", 0)
passed = high_count > 0
print_result(
    "Test 5: Multi-signal -> higher severity score",
    passed,
    f"Some alerts for {MULTI_SIGNAL_EMP} reach 'high' severity (3 signals combined)",
    f"Severity breakdown for {MULTI_SIGNAL_EMP}: {dict(severity_counts)}"
)

# ---------------- TEST 6: Alert data completeness ----------------
sample_query = {"query": {"match_all": {}}}
sample = client.search(index=ALERTS_INDEX, body={"size": 1, **sample_query})
required_fields = ["alert_id", "employee_id", "event_id", "timestamp", "reasons", "severity"]
if sample["hits"]["hits"]:
    doc = sample["hits"]["hits"][0]["_source"]
    missing = [f for f in required_fields if f not in doc or doc[f] in (None, "", [])]
    passed = len(missing) == 0
    print_result(
        "Test 6: Alert data completeness",
        passed,
        f"All required fields present: {required_fields}",
        f"Sample alert record: {doc}" + (f" | MISSING: {missing}" if missing else " | All fields present")
    )
else:
    print_result("Test 6: Alert data completeness", False, "At least one alert record to inspect", "No alerts found in index")

# ---------------- TEST 7: Precision/Recall against full dataset ----------------
SOURCE_INDEX = "access-logs"

print("Running Test 7 - this scans all 100,000 records, please wait...")
truth_by_event = {}
for doc in helpers.scan(client, index=SOURCE_INDEX, query={"query": {"match_all": {}}}, size=1000):
    src = doc["_source"]
    truth_by_event[src["event_id"]] = src["is_suspicious"]

all_alerts = list(helpers.scan(client, index=ALERTS_INDEX, query={"query": {"match_all": {}}}, size=1000))
alerted_event_ids = {a["_source"]["event_id"] for a in all_alerts}

true_positives = sum(1 for eid in alerted_event_ids if truth_by_event.get(eid) == 1)
false_positives = sum(1 for eid in alerted_event_ids if truth_by_event.get(eid) == 0)

suspicious_event_ids = {eid for eid, v in truth_by_event.items() if v == 1}
false_negatives = len(suspicious_event_ids - alerted_event_ids)

precision = true_positives / len(alerted_event_ids) if alerted_event_ids else 0
recall = true_positives / len(suspicious_event_ids) if suspicious_event_ids else 0

# Pass threshold: recall >= 90% and precision >= 95% (reasonable bar for a rule-based detector)
passed = recall >= 0.90 and precision >= 0.95
print_result(
    "Test 7: Precision/Recall against full dataset",
    passed,
    "Recall >= 90% and Precision >= 95% against is_suspicious ground truth",
    f"Precision: {precision:.2%} ({true_positives} TP / {len(alerted_event_ids)} total alerts) | "
    f"Recall: {recall:.2%} ({true_positives} TP / {len(suspicious_event_ids)} planted-suspicious) | "
    f"False positives: {false_positives} | False negatives (missed): {false_negatives}"
)

print("=" * 60)
print("END OF TEST MATRIX")
print("=" * 60)
