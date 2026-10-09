from opensearchpy import OpenSearch, helpers
import csv

client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False
)

index_name = "access-logs"

# Delete the index if it already exists, so we always start fresh
if client.indices.exists(index=index_name):
    client.indices.delete(index=index_name)

mapping = {
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "employee_id": {"type": "keyword"},
            "employee_role": {"type": "keyword"},
            "assigned_segment": {"type": "keyword"},
            "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ssZ"},
            "action": {"type": "keyword"},
            "customer_record_id": {"type": "keyword"},
            "accessed_segment": {"type": "keyword"},
            "source_ip": {"type": "ip"},
            "session_duration_minutes": {"type": "integer"},
            "is_suspicious": {"type": "integer"}
        }
    }
}

client.indices.create(index=index_name, body=mapping)

def generate_docs():
    with open("access_logs.csv", "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["session_duration_minutes"] = int(row["session_duration_minutes"])
            row["is_suspicious"] = int(row["is_suspicious"])
            yield {
                "_index": index_name,
                "_source": row
            }

success, failed = helpers.bulk(client, generate_docs(), raise_on_error=False)

client.indices.refresh(index=index_name)  # force refresh so count is accurate right away

count = client.count(index=index_name)["count"]

print(f"Successfully indexed: {success}")
print(f"Failed: {failed if isinstance(failed, int) else len(failed)}")
print(f"Total documents in index: {count}")
