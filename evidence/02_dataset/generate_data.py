import csv
import random
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

random.seed(42)  # fixed seed so the dataset is exactly reproducible on every run

EAT = ZoneInfo("Africa/Nairobi")

roles = ["support_agent", "analyst", "manager", "billing_clerk"]
segments = ["east_africa", "west_africa", "north_africa", "southern_africa"]

num_employees = 200
employees = []
for i in range(1, num_employees + 1):
    employee_id = f"EMP{i:04d}"
    role = random.choice(roles)
    assigned_segment = random.choice(segments)
    normal_ips = [f"10.0.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(2)]
    employees.append({
        "employee_id": employee_id,
        "role": role,
        "assigned_segment": assigned_segment,
        "normal_ips": normal_ips
    })

off_hours_employees = [e["employee_id"] for e in employees[:10]]
bulk_employees = [e["employee_id"] for e in employees[10:20]]
scope_employees = [e["employee_id"] for e in employees[20:30]]
multi_signal_employees = [e["employee_id"] for e in employees[30:35]]

actions = ["login", "file_access", "download", "export"]

start_date = datetime(2026, 6, 1, tzinfo=EAT)
end_date = datetime(2026, 6, 30, tzinfo=EAT)

def random_business_hour_timestamp():
    day_offset = random.randint(0, (end_date - start_date).days)
    day = start_date + timedelta(days=day_offset)
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=random.randint(0, 59))

def random_off_hour_timestamp():
    day_offset = random.randint(0, (end_date - start_date).days)
    day = start_date + timedelta(days=day_offset)
    hour = random.choice(list(range(0, 6)) + list(range(20, 24)))
    minute = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=random.randint(0, 59))

rows = []
event_counter = 1

def add_row(employee, timestamp, accessed_segment, source_ip, session_duration, is_suspicious):
    global event_counter
    rows.append({
        "event_id": f"EVT{event_counter:07d}",
        "employee_id": employee["employee_id"],
        "employee_role": employee["role"],
        "assigned_segment": employee["assigned_segment"],
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S%z"),
        "action": random.choice(actions),
        "customer_record_id": f"CUST{random.randint(1,50000):05d}",
        "accessed_segment": accessed_segment,
        "source_ip": source_ip,
        "session_duration_minutes": session_duration,
        "is_suspicious": is_suspicious
    })
    event_counter += 1

# ---------------------------------------------------------------------
# track each bulk/multi-signal employee's planted burst window,
# so normal events can never accidentally be drawn inside it.
# ---------------------------------------------------------------------
burst_windows = {}  # employee_id -> (start_timestamp, end_timestamp)

def redraw_if_overlapping(employee_id, timestamp, generator_func):
    """If this timestamp falls inside this employee's own burst window, redraw it."""
    window = burst_windows.get(employee_id)
    while window is not None and window[0] <= timestamp <= window[1]:
        timestamp = generator_func()
    return timestamp

# ---------------- Generate bulk-volume bursts first, so we know their windows ----------------
bulk_burst_rows = []
for emp_id in bulk_employees:
    employee = next(e for e in employees if e["employee_id"] == emp_id)
    base_timestamp = random_business_hour_timestamp()
    burst_start = base_timestamp - timedelta(minutes=10)
    burst_end = base_timestamp + timedelta(seconds=299 * 2) + timedelta(minutes=10)
    burst_windows[emp_id] = (burst_start, burst_end)
    for i in range(300):
        timestamp = base_timestamp + timedelta(seconds=i * 2)
        source_ip = random.choice(employee["normal_ips"])
        session_duration = random.randint(1, 5)
        bulk_burst_rows.append((employee, timestamp, employee["assigned_segment"], source_ip, session_duration, 1))

# ---------------- Generate multi-signal bursts, recording their windows too ----------------
multi_signal_rows = []
for emp_id in multi_signal_employees:
    employee = next(e for e in employees if e["employee_id"] == emp_id)
    base_timestamp = random_off_hour_timestamp()
    wrong_segment = random.choice([s for s in segments if s != employee["assigned_segment"]])
    unknown_ip = f"203.0.{random.randint(1,254)}.{random.randint(1,254)}"
    burst_start = base_timestamp - timedelta(minutes=10)
    burst_end = base_timestamp + timedelta(seconds=199 * 2) + timedelta(minutes=10)
    burst_windows[emp_id] = (burst_start, burst_end)
    for i in range(200):
        timestamp = base_timestamp + timedelta(seconds=i * 2)
        session_duration = random.randint(1, 5)
        multi_signal_rows.append((employee, timestamp, wrong_segment, unknown_ip, session_duration, 1))

# ---------------- Now generate the 95,000 normal events, redrawing on overlap ----------------
target_normal_records = 95000
for _ in range(target_normal_records):
    employee = random.choice(employees)
    timestamp = random_business_hour_timestamp()
    timestamp = redraw_if_overlapping(employee["employee_id"], timestamp, random_business_hour_timestamp)
    source_ip = random.choice(employee["normal_ips"])
    session_duration = random.randint(2, 30)
    add_row(employee, timestamp, employee["assigned_segment"], source_ip, session_duration, 0)

# ---------------- Add the bulk and multi-signal rows generated above ----------------
for employee, timestamp, seg, ip, dur, sus in bulk_burst_rows:
    add_row(employee, timestamp, seg, ip, dur, sus)

for employee, timestamp, seg, ip, dur, sus in multi_signal_rows:
    add_row(employee, timestamp, seg, ip, dur, sus)

# ---------------- Off-hours group (no burst window, so no overlap risk) ----------------
for emp_id in off_hours_employees:
    employee = next(e for e in employees if e["employee_id"] == emp_id)
    for _ in range(50):
        timestamp = random_off_hour_timestamp()
        source_ip = random.choice(employee["normal_ips"])
        session_duration = random.randint(2, 30)
        add_row(employee, timestamp, employee["assigned_segment"], source_ip, session_duration, 1)

# ---------------- Scope-violation group (no burst window, so no overlap risk) ----------------
for emp_id in scope_employees:
    employee = next(e for e in employees if e["employee_id"] == emp_id)
    for _ in range(50):
        timestamp = random_business_hour_timestamp()
        wrong_segment = random.choice([s for s in segments if s != employee["assigned_segment"]])
        source_ip = random.choice(employee["normal_ips"])
        session_duration = random.randint(2, 30)
        add_row(employee, timestamp, wrong_segment, source_ip, session_duration, 1)

random.shuffle(rows)

fieldnames = [
    "event_id", "employee_id", "employee_role", "assigned_segment",
    "timestamp", "action", "customer_record_id", "accessed_segment",
    "source_ip", "session_duration_minutes", "is_suspicious"
]

with open("access_logs.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Total records generated: {len(rows)}")
print(f"Suspicious records: {sum(1 for r in rows if r['is_suspicious'] == 1)}")
