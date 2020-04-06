import boto3
import os

dynamo = boto3.client('dynamodb', 
    endpoint_url =
        "https://dynamodb." +
        os.environ.get("AWS_REGION") +
        "." +
        os.environ.get("aws_domain"))

def get_ca_public_key(key_name, projection):
    try:
        response = dynamo.get_item(
            TableName=os.environ.get('ssh_dynamo_ca_table_name'),
            Key={
                'key_name': {'S': key_name }
            },
            ProjectionExpression=projection)
        if 'Item' not in response:
            return None
        return response['Item']
    except dynamo.exceptions.ResourceNotFoundException as e:
        return None

def get_user(public_key, ca_key_name):
    try:
        response = dynamo.get_item(
            TableName=os.environ.get('ssh_dynamo_user_table_name'),
            Key={
                'public_key': {'S': public_key },
                'ca': {'S': ca_key_name}
            },
            ProjectionExpression='user_roles,audited_username')
        if 'Item' not in response:
            return None
        return response['Item']
    except dynamo.exceptions.ResourceNotFoundException as e:
        return None
