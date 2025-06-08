import json
import boto3
import os
from datetime import datetime
import time
import random
import re
from botocore.exceptions import ClientError

# Global variable to store the last processed message
last_message = None

def get_latest_log_file(s3_client, bucket_name, prefix='Log/'):
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' not in response:
            print("No log files found in S3 bucket.")
            return None
        latest_file = max(response['Contents'], key=lambda x: x['LastModified'])
        return latest_file['Key']
    except Exception as e:
        print(f"Error listing S3 objects: {str(e)}")
        return None

def invoke_bedrock_with_retry(bedrock_client, model_id, body, max_retries=5):
    for attempt in range(max_retries):
        try:
            response = bedrock_client.invoke_model(
                modelId=model_id,
                contentType='application/json',
                accept='application/json',
                body=body
            )
            return response
        except ClientError as e:
            if e.response['Error']['Code'] == 'ThrottlingException':
                if attempt == max_retries - 1:
                    raise e
                delay = min(32, (2 ** attempt) + random.uniform(0, 0.1))
                print(f"ThrottlingException on attempt {attempt + 1}, retrying after {delay:.2f}s")
                time.sleep(delay)
            else:
                raise e
    raise Exception("Max retries reached for Bedrock invocation")

def send_email(ses_client, sender, recipient, subject, body):
    global last_message
    try:
        # Ensure body is a string
        event_message = str(body)
        
        # Regex pattern to match JSON block (simplified and robust)
        json_pattern = r'```json\n([\s\S]*?)\n```'
        json_match = re.search(json_pattern, event_message)
        
        if json_match:
            json_content = json_match.group(1)
            if json_content != last_message:
                try:
                    # Parse to validate JSON
                    json_data = json.loads(json_content)
                    # Update last_message to avoid duplicate logging
                    last_message = json_content
                    print("Filtered SES JSON Output:", json.dumps(json_data, indent=2))
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from SES output: {str(e)}")
                    return {
                        'statusCode': 500,
                        'body': json.dumps(f"Error decoding JSON from SES output: {str(e)}")
                    }
            else:
                print("Duplicate SES message detected, skipping logging.")
        else:
            print("No JSON block found in SES output.")
        
        # Send the email
        response = ses_client.send_email(
            Source=sender,
            Destination={
                'ToAddresses': [recipient]
            },
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': event_message,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        print(f"Email sent! Message ID: {response['MessageId']}")
        return response
    except ClientError as e:
        print(f"Error sending email: {str(e)}")
        raise e

def lambda_handler(event, context):
    # Initialize AWS clients
    s3_client = boto3.client('s3')
    bedrock_client = boto3.client('bedrock-runtime', region_name='ap-southeast-1')
    ses_client = boto3.client('ses', region_name='ap-southeast-1')
    
    # Environment variables
    bucket_name = os.environ.get('BUCKET_NAME', 'ExampleBucket')
    sender_email = os.environ.get('SENDER_EMAIL', 'ExampleEmail')  # Must be verified in SES
    recipient_email = os.environ.get('RECIPIENT_EMAIL', 'ExampleEmail')     # Recipient email
    
    # Get the latest log file
    latest_file_key = get_latest_log_file(s3_client, bucket_name)
    if not latest_file_key:
        return {
            'statusCode': 404,
            'body': json.dumps('No log files found')
        }
    
    # Read the JSON file from S3
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=latest_file_key)
        log_data = json.loads(response['Body'].read().decode('utf-8'))
    except Exception as e:
        print(f"Error reading S3 file: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error reading S3 file: {str(e)}")
        }
    
    # Define the prompt for Bedrock (Claude format)
    prompt = (
        "You are a cybersecurity AI helping detect suspicious network activity from logs. "
        "Analyze the following network log and determine whether the behavior is suspicious. If yes, explain why. "
        "Respond in **valid JSON** format with the following fields: "
        "- source_ip (string): Copy from the input. "
        "- destination_ip (string): Copy from the input. "
        "- is_suspicious (boolean): true if this behavior is abnormal or malicious. "
        "- reason (string): Short explanation of why the activity is suspicious (or not). "
        "- suggested_action (string): Recommendation on what to do next. "
        "Ensure the response is strictly valid JSON, wrapped in triple backticks (```json\n<response>\n```). "
        "Return only the JSON block, nothing else. Log data:\n"
        f"{json.dumps(log_data, indent=2)}\n"
        "Example response:\n"
        "```json\n"
        "{\"source_ip\": \"example\", \"destination_ip\": \"example\", \"is_suspicious\": false, \"reason\": \"No issues detected\", \"suggested_action\": \"Monitor\"}\n"
        "```"
    )
    
    # Invoke Bedrock
    try:
        bedrock_response = invoke_bedrock_with_retry(
            bedrock_client,
            model_id='anthropic.claude-v2',
            body=json.dumps({
                'messages': [{'role': 'user', 'content': prompt}],
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 512,
                'temperature': 0.7,
                'top_p': 0.9
            }),
            max_retries=5
        )
        
        # Parse Bedrock response
        result = json.loads(bedrock_response['body'].read().decode('utf-8'))
        print("Bedrock Output:", result)
        
        # Extract the text field containing the JSON block
        email_body = result['content'][0]['text'] if result.get('content') and len(result['content']) > 0 else ''
        if not email_body:
            raise ValueError("No text content found in Bedrock response")
        
        # Send email with Bedrock output
        email_subject = "Bedrock Analysis Result for Network Log"
        send_email(ses_client, sender_email, recipient_email, email_subject, email_body)
        
        # Parse JSON block for Lambda response
        json_pattern = r'```json\n([\s\S]*?)\n```'
        json_match = re.search(json_pattern, email_body)
        if json_match:
            json_content = json_match.group(1)
            parsed_json = json.loads(json_content)
            return {
                'statusCode': 200,
                'body': json.dumps(parsed_json)
            }
        else:
            raise ValueError("No valid JSON block found in Bedrock response")
            
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing request: {str(e)}")
        }
