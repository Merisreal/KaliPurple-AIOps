import json
import time
import requests
from elasticsearch import Elasticsearch
from datetime import datetime, timezone
import urllib3
import re
from collections import Counter

# Suppress SSL warnings (only for testing; use certificates in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
ELASTICSEARCH_HOST = "https://localhost:9200"
ELASTICSEARCH_USERNAME = "elastic"
ELASTICSEARCH_PASSWORD = "ExampleKey"
INDEX_NAME = ".ds-filebeat-8.18.1-2025.05.26-000001"
ALERT_INDEX_NAME = "chatbot_alerts"
OPENROUTER_API_KEY = "sk-or-v1-ExampleKey"
OPENROUTER_API_URL = "ExampleKeyURL"
KIBANA_URL = "http://localhost:5601"  # Adjust if Kibana runs on a different host/port
ZEEK_LOG_PATH = "/usr/local/zeek/logs/current/conn.log"
MAX_RETRIES = 3
RETRY_DELAY = 60  # Increased to handle 429 errors
LOG_BUFFER_SIZE = 100  # Number of logs to collect before sending
BUFFER_TIMEOUT = 30  # Max seconds to wait for 15 logs
POLL_INTERVAL = 30  # Polling interval in seconds

# Initialize Elasticsearch client
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
    verify_certs=False
)

def create_alert_index():
    """Create an Elasticsearch index for chatbot alerts if it doesn't exist."""
    mapping = {
        "mappings": {
            "properties": {
                "source_ip": {"type": "keyword"},
                "destination_ip": {"type": "keyword"},
                "connection_count": {"type": "integer"},
                "flags": {"type": "keyword"},
                "duration": {"type": "float"},
                "timestamp": {"type": "date"}
            }
        }
    }
    try:
        if not es.indices.exists(index=ALERT_INDEX_NAME):
            es.indices.create(index=ALERT_INDEX_NAME, body=mapping)
            print(f"Index '{ALERT_INDEX_NAME}' created successfully")
        else:
            print(f"Index '{ALERT_INDEX_NAME}' already exists")
    except Exception as e:
        print(f"Error creating index '{ALERT_INDEX_NAME}': {e}")

def create_kibana_data_view():
    """Create a Kibana Data View for the chatbot_alerts index."""
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
    data_view_payload = {
        "data_view": {
            "title": ALERT_INDEX_NAME,
            "name": "Chatbot Alerts",
            "timeFieldName": "timestamp"
        }
    }
    try:
        response = requests.post(
            f"{KIBANA_URL}/api/data_views/data_view",
            auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
            headers=headers,
            data=json.dumps(data_view_payload)
        )
        response.raise_for_status()
        print(f"Data View 'Chatbot Alerts' created successfully")
    except requests.exceptions.RequestException as e:
        print(f"Error creating Data View: {e}")

def parse_chatbot_output(output):
    """Parse chatbot output into a structured JSON object."""
    try:
        # Expected format: Src:<source_ip> - Dst:<destination_ip> - Connection Count:<count> - Flags:<flags> - Duration:<duration>
        pattern = r"Src:([\d\.]+)\s*-\s*Dst:([\d\.]+)\s*-\s*Connection Count:(\d+)\s*-\s*Flags:([\w,]+)\s*-\s*Duration:([\d\.xXa-fA-F]+)"
        match = re.match(pattern, output.strip())
        if not match:
            raise ValueError(f"Invalid chatbot output format: {output}")
        
        source_ip, destination_ip, connection_count, flags, duration = match.groups()
        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "connection_count": int(connection_count),
            "flags": flags,
            "duration": float(duration) if not any(c in duration.lower() for c in 'abcdef') else duration,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        print(f"Error parsing chatbot output: {e}")
        return None

def index_chatbot_output(output):
    """Index the parsed chatbot output into Elasticsearch."""
    parsed_output = parse_chatbot_output(output)
    if not parsed_output:
        return
    try:
        es.index(index=ALERT_INDEX_NAME, body=parsed_output)
        print(f"Indexed chatbot output to '{ALERT_INDEX_NAME}'")
    except Exception as e:
        print(f"Error indexing chatbot output: {e}")

def query_new_logs(last_timestamp):
    """Query Elasticsearch for recent Zeek conn.log entries with source IP 192.168.1.10."""
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"log.file.path": ZEEK_LOG_PATH}},
                    {"term": {"source.ip": "192.168.1.10"}},
                    {"range": {"@timestamp": {"gt": last_timestamp}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }
    try:
        response = es.search(index=INDEX_NAME, body=query)
        logs = response["hits"]["hits"][::-1]  # Reverse to process oldest to newest
        return logs
    except Exception as e:
        print(f"Error querying Elasticsearch: {str(e)}")
        return []

def send_to_openrouter(logs):
    """Send a batch of logs to meta-llama/llama-3.3-8b-instruct via OpenRouter API."""
    if not logs:
        print("No logs to send to chatbot.")
        return None
    
    # Filter and map log fields
    def filter_log_fields(log):
        source = log["_source"]
        duration = source.get("event", {}).get("duration", 0) / 1_000_000_000  # Convert nanoseconds to seconds
        duration = float(f"{duration:.4f}")  # Format to 4 decimal places
        return {
            "ts": source.get("@timestamp"),
            "id.orig_h": source.get("source", {}).get("ip"),
            "id.orig_p": source.get("source", {}).get("port"),
            "id.resp_h": source.get("destination", {}).get("ip"),
            "id.resp_p": source.get("destination", {}).get("port"),
            "proto": source.get("network", {}).get("transport"),
            "conn_state": source.get("zeek", {}).get("connection", {}).get("state"),
            "history": source.get("zeek", {}).get("connection", {}).get("history"),
            "duration": duration,
            "orig_bytes": source.get("source", {}).get("bytes"),
            "resp_bytes": source.get("destination", {}).get("bytes"),
            "orig_pkts": source.get("source", {}).get("packets"),
            "resp_pkts": source.get("destination", {}).get("packets")
        }
    
    log_data = [filter_log_fields(log) for log in logs]
    
    # Find the most frequent source IP and destination IP pair
    ip_pairs = [(log["id.orig_h"], log["id.resp_h"]) for log in log_data]
    most_common_pair = Counter(ip_pairs).most_common(1)
    if not most_common_pair:
        print("No valid IP pairs found.")
        return None
    (src_ip, dst_ip), count = most_common_pair[0]
    
    # Filter logs for the most common IP pair
    filtered_logs = [log for log in log_data if log["id.orig_h"] == src_ip and log["id.resp_h"] == dst_ip]
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    prompt = """
You are given a list of network connection logs in JSON format. Each log entry represents one network connection and contains the following fields:

ts: timestamp of the connection  
id.orig_h: source IP  
id.orig_p: source port  
id.resp_h: destination IP  
id.resp_p: destination port  
proto: transport protocol (e.g., tcp, udp)  
conn_state: Zeek connection state (e.g., REJ, SF)  
history: TCP history (e.g., Sr, Dd, S0)  
duration: duration of the connection  
orig_bytes / resp_bytes: bytes sent/received  
orig_pkts / resp_pkts: number of packets  

Analyze logs for the most frequent source IP and destination IP pair (provided in the logs).

For this IP pair, generate the following summary:
- `Connection Count:` is the total number of logs for the most frequent source IP and destination IP pair.
- `Flags:` should summarize the common TCP flags observed based on the `history` field. Extract each character from `history` and separate them by commas. For example, "Sr" should be output as "S,r".
- The meanings of flags in history are:
  - 'S' = SYN 
  - 'r' = reset 
- `Duration:` is the first `duration` value found among the filtered logs for this IP pair.
  - If it is in hexadecimal format, keep it unchanged.
  - If it is a float, only print up to **4 digits after the decimal point**, without rounding beyond that.
    - Example: 0.00006890296936035156 → 0.0000
- Also print the destination IP (`id.resp_h`) corresponding to that first matching log.

Print exactly one single line in this format:

Src:<source_ip> - Dst:<destination_ip> - Connection Count:<count> - Flags:<flags_from_history> - Duration:<first_duration_value>

Only return this one line. Do not include any explanation or multiple lines.
"""
    
    full_prompt = f"{prompt}\n\nLogs:\n{json.dumps(filtered_logs, indent=2)}"
    payload = {
        "model": "meta-llama/llama-3.3-8b-instruct:free",
        "messages": [{"role": "user", "content": full_prompt}]
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(OPENROUTER_API_URL, headers=headers, data=json.dumps(payload))
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"Attempt {attempt + 1}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            continue
    print("All retry attempts failed.")
    return None

def main():
    # Create alert index and Data View at startup
    create_alert_index()
    create_kibana_data_view()

    last_timestamp = datetime.now(timezone.utc).isoformat()
    print(f"Monitoring Zeek conn.log entries from {ZEEK_LOG_PATH}...")
    log_buffer = []  # Buffer to collect logs
    buffer_start_time = time.time()

    while True:
        logs = query_new_logs(last_timestamp)
        if logs:
            # Add each log as a separate entry, even if timestamps are identical
            for log in logs:
                log_buffer.append(log)
            print(f"Found {len(logs)} new conn.log entries, total buffered: {len(log_buffer)}")
            if logs:
                last_timestamp = max(log["_source"]["@timestamp"] for log in logs)

        # Process when buffer has 15 logs or timeout is reached
        if len(log_buffer) >= LOG_BUFFER_SIZE or (log_buffer and time.time() - buffer_start_time >= BUFFER_TIMEOUT):
            print(f"Sending {min(len(log_buffer), LOG_BUFFER_SIZE)} logs to OpenRouter...")
            gemma_response = send_to_openrouter(log_buffer[:LOG_BUFFER_SIZE])
            if gemma_response:
                print(gemma_response)
                index_chatbot_output(gemma_response)
            else:
                print("Failed to get response from meta-llama/llama-3.3-8b-instruct")
            log_buffer = log_buffer[LOG_BUFFER_SIZE:]  # Remove processed logs, keep any extras
            buffer_start_time = time.time()  # Reset timer
            print(f"Buffer reset, remaining logs: {len(log_buffer)}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
