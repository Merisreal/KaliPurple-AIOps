import json
import time
import boto3
import os
import tempfile
from elasticsearch import Elasticsearch
from datetime import datetime, timezone
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
ELASTICSEARCH_HOST = "https://localhost:9200"
ELASTICSEARCH_USERNAME = "elastic"
ELASTICSEARCH_PASSWORD = "ExampleKey"
ALERT_INDEX_NAME = "chatbot_alerts"
S3_BUCKET_NAME = "ExampleBucket"  
AWS_REGION = "ap-southeast-1"  
AWS_ACCESS_KEY_ID = "ExampleKey" 
AWS_SECRET_ACCESS_KEY = "ExampleKeyS"  
CHECK_INTERVAL = 5  

es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
    verify_certs=False
)

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

def get_latest_alert():
    """Query Elasticsearch for the latest record in chatbot_alerts index."""
    query = {
        "query": {
            "match_all": {}
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 1
    }
    try:
        response = es.search(index=ALERT_INDEX_NAME, body=query)
        hits = response["hits"]["hits"]
        if hits:
            return hits[0]["_source"]
        return None
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")
        return None

def upload_to_s3(alert):
    """Upload the alert to S3 bucket as a JSON file."""
    try:
        # Create file name based on timestamp
        timestamp_str = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")).strftime("%Y-%m-%dT%H-%M-%S")
        file_name = f"chatbot_output_{timestamp_str}.json"
        
        # Create a temporary file for the JSON data
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(alert, temp_file, indent=2)
            temp_file_path = temp_file.name
        
        # Upload to S3
        s3_client.upload_file(temp_file_path, S3_BUCKET_NAME, file_name)
        print(f"Uploaded alert to S3: s3://{S3_BUCKET_NAME}/{file_name}")
        
        # Clean up temporary file
        os.remove(temp_file_path)
        return file_name
    except Exception as e:
        print(f"Error uploading to S3: {e}")
        return None

def main():
    last_uploaded_timestamp = None
    print(f"Monitoring {ALERT_INDEX_NAME} for new chatbot alerts to upload to S3...")
    
    while True:
        # Get the latest alert
        latest_alert = get_latest_alert()
        if not latest_alert:
            print("No alerts found in index. Waiting for next check...")
            time.sleep(CHECK_INTERVAL)
            continue
        
        current_timestamp = latest_alert["timestamp"]
        
        # Check if this alert is new (not uploaded yet)
        if last_uploaded_timestamp != current_timestamp:
            print(f"New alert found with timestamp: {current_timestamp}")
            # Wait 5 minutes before uploading to ensure no newer alert appears
            print(f"Waiting {CHECK_INTERVAL} seconds before uploading...")
            time.sleep(CHECK_INTERVAL)
            
            # Re-check to ensure this is still the latest alert
            latest_alert_check = get_latest_alert()
            if latest_alert_check and latest_alert_check["timestamp"] == current_timestamp:
                # Upload the alert to S3
                uploaded_file = upload_to_s3(latest_alert)
                if uploaded_file:
                    last_uploaded_timestamp = current_timestamp
                    print(f"Updated last uploaded timestamp: {last_uploaded_timestamp}")
            else:
                print(f"Newer alert found during wait period. Skipping upload for {current_timestamp}")
        else:
            print(f"No new alerts. Latest timestamp {current_timestamp} already uploaded.")
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()


