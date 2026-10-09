# Insider Threat Detection

A rule-based insider threat detection pipeline built with Docker, OpenSearch, and Python. It generates synthetic employee access logs, loads them into OpenSearch, flags suspicious activity, and visualizes the alerts in OpenSearch Dashboards.

## Detection Signals

- **Off-hours access:** activity outside business hours (8am to 6pm)
- **Scope violation:** access to resources outside an employee's normal scope
- **Bulk volume:** 50 or more events within a 10 minute rolling window

Alert severity increases with the number of signals triggered on an event.

## Tech Stack

- Python 3 with `opensearch-py`
- OpenSearch 2.15.0 and OpenSearch Dashboards 2.15.0
- Docker Compose

## Project Structure

```
docker-compose.yml   OpenSearch and Dashboards setup
scripts/             Data generation, loading, detection, and testing scripts
evidence/            Screenshots and outputs for each stage (01 to 07)
reports/             Final project report (PDF)
```

## Prerequisites

- Docker Desktop installed and running
- Python 3

## Getting Started

1. Start the environment:
```bash
   docker compose up -d
```
2. Install the dependency:
```bash
   pip install opensearch-py
```
3. Run the pipeline from the `scripts/` folder:
```bash
   python generate_data.py
   python load_to_opensearch.py
   python detect_threats.py
   python verify_alerts.py
```
4. Open http://localhost:5601 in your browser (only works on the machine running Docker).
5. Go to Stack Management, then Index Patterns, and create two index patterns: `access-logs` and `alerts`. When asked for a time field, choose the timestamp field.
6. Build your visualizations in Dashboards. See `evidence/06_dashboard/` for screenshots of the finished dashboard to use as a reference.

## Testing

`investigate_fp_fn.py` and `test_matrix.py` analyze false positives and false negatives of the detection rules.

## Notes

- Security is disabled in `docker-compose.yml` for local development only. Do not use this setup in production.
- All data is synthetic.

## Authors

Group 2 Students of DSA3040UA - Summer,2026 , USIU-Africa 
