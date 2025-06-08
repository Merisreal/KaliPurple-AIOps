import boto3
import os
from datetime import datetime
from botocore.config import Config
import time
import re
import json
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case, CaseObservable
import uuid

# TheHive configuration
THEHIVE_URL = 'http://localhost:9000'
THEHIVE_API_KEY = 'ExampleKey+ExampleKey+ExampleKey'  # Provided TheHive API key

def should_convert_to_case(json_data):
    """Determine if the alert should be converted to a case."""
    # Check if is_suspicious is True or if reason contains specific keywords
    is_suspicious = json_data.get('is_suspicious', False)
    reason = json_data.get('reason', '').lower()
    keywords = ['brute force', 'port scan']
    return is_suspicious or any(keyword in reason for keyword in keywords)

def create_thehive_case(api, alert_id, json_data):
    """Create a case in TheHive from the alert data."""
    try:
        case_id = str(uuid.uuid4())
        case = Case(
            title=f"Case from Bedrock Alert: {alert_id}",
            tlp=2,
            tags=['network', 'bedrock', 'aws', 'suspicious', 'auto-generated'],
            description=f"Case created from alert ID: {alert_id}\n\nJSON Data:\n{json.dumps(json_data, indent=2)}",
            severity=2,  # Medium severity
            flag=False,
            sourceRef=case_id,
            source='cloudwatch-logs'
        )

        # Add observables (equivalent to alert artifacts)
        case.observables = []
        for key, value in json_data.items():
            if key in ['source_ip', 'destination_ip']:
                case.observables.append(
                    CaseObservable(dataType='ip', data=str(value), message=f'{key.replace("_", " ").title()}')
                )
            elif key == 'reason':
                case.observables.append(
                    CaseObservable(dataType='other', data=str(value), message='Reason')
                )
            elif key == 'suggested_action':
                case.observables.append(
                    CaseObservable(dataType='other', data=str(value), message='Suggested Action')
                )
            else:
                case.observables.append(
                    CaseObservable(dataType='other', data=str(value), message=key.replace('_', ' ').title())
                )

        # Create the case
        response = api.create_case(case)
        if response.status_code == 201:
            print(f"✅ Case created in TheHive (ID: {response.json()['id']})")
            return response.json()['id']
        else:
            print(f"❌ Error creating case: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Error creating case: {e}")
        return None

def get_latest_bedrock_log():
    aws_access_key_id = "ExampleKey"
    aws_secret_access_key = "ExampleKey"
    region_name = "ap-southeast-1"
    log_group_name = "/aws/lambda/ExampleBucket"
    log_stream_name = "ExampleBucketLogf"
    
    boto_config = Config(
        region_name=region_name,
        retries={'max_attempts': 5, 'mode': 'standard'},
        connect_timeout=10,
        read_timeout=30
    )

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name
        )
        client = session.client(
            'logs',
            config=boto_config,
            endpoint_url=f'https://logs.{region_name}.amazonaws.com'
        )
    except Exception as e:
        print(f"Error initializing AWS client: {e}")
        return

    # Initialize TheHive API
    try:
        api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
    except Exception as e:
        print(f"Error initializing TheHive API: {e}")
        return

    last_message = None  # Track the last JSON block to avoid duplicates
    json_pattern = r'```json\\n{[\s\S]*?}\\n```'

    kwargs = {
        'logGroupName': log_group_name,
        'logStreamNames': [log_stream_name],
        'filterPattern': '"Bedrock Output:"',
        'limit': 100  # Reduced limit for efficiency
    }

    while True:
        try:
            events = []
            while True:
                response = client.filter_log_events(**kwargs)
                events.extend(response.get('events', []))
                if 'nextToken' not in response:
                    break
                kwargs['nextToken'] = response['nextToken']

            # Find the latest event by timestamp
            if events:
                latest_event = max(events, key=lambda x: x['timestamp'])
                event_message = latest_event['message']

                # Extract JSON block using regex
                json_match = re.search(json_pattern, event_message)
                if json_match:
                    json_content = json_match.group(0)
                    if json_content != last_message:
                        try:
                            # Remove ```json\n``` prefix and ``` suffix
                            raw_json = json_content[len('```json\\n'):-len('\\n```')]
                            # Decode escaped characters
                            unescaped_json = raw_json.encode().decode('unicode_escape')
                            # Parse to validate JSON
                            json_data = json.loads(unescaped_json)

                            # Create alert for TheHive
                            alert_id = str(uuid.uuid4())
                            alert = Alert(
                                title='Bedrock Log Alert',
                                tlp=2,
                                tags=['network', 'bedrock', 'aws', 'suspicious'],
                                description=json.dumps(json_data, indent=2),
                                type='external',
                                source='cloudwatch-logs',
                                sourceRef=alert_id
                            )

                            # Add artifacts dynamically from JSON data
                            alert.artifacts = []
                            for key, value in json_data.items():
                                if key in ['source_ip', 'destination_ip']:
                                    alert.artifacts.append(
                                        AlertArtifact(dataType='ip', data=str(value), message=f'{key.replace("_", " ").title()}')
                                    )
                                elif key == 'reason':
                                    alert.artifacts.append(
                                        AlertArtifact(dataType='other', data=str(value), message='Reason')
                                    )
                                elif key == 'suggested_action':
                                    alert.artifacts.append(
                                        AlertArtifact(dataType='other', data=str(value), message='Suggested Action')
                                    )
                                else:
                                    alert.artifacts.append(
                                        AlertArtifact(dataType='other', data=str(value), message=key.replace('_', ' ').title())
                                    )

                            # Send alert to TheHive
                            response = api.create_alert(alert)
                            if response.status_code == 201:
                                print(f"✅ Alert sent to TheHive (ID: {response.json()['id']})")
                                # Check if the alert should be converted to a case
                                if should_convert_to_case(json_data):
                                    case_id = create_thehive_case(api, response.json()['id'], json_data)
                                    if case_id:
                                        print(f"✅ Case linked to alert ID: {response.json()['id']}")
                            else:
                                print(f"❌ Error sending alert: {response.status_code}, {response.text}")

                            last_message = json_content
                        except (json.JSONDecodeError, Exception) as e:
                            print(f"Error processing JSON or sending alert: {e}")
                            pass

        except Exception as e:
            print(f"Error fetching logs: {e}")
            pass

        time.sleep(10)  # Wait 10 seconds before the next check
        kwargs.pop('nextToken', None)  # Reset pagination for the next fetch

if __name__ == "__main__":
    try:
        get_latest_bedrock_log()
    except KeyboardInterrupt:
        print("Stopped by user.")
