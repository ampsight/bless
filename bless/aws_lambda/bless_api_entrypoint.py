import os
import json
import traceback
from bless.persistence.dynamo_operations import get_user, get_ca_public_key
from bless.persistence.key_management import restore_bless_cache, save_bless_cache, set_ca_key
from bless.aws_lambda.bless_lambda_common import success_response, error_response, set_logger
from bless.aws_lambda.bless_lambda_user import lambda_handler_user
from bless.aws_lambda.bless_lambda_host import lambda_handler_host
from marshmallow.exceptions import ValidationError
from marshmallow import Schema, fields

def form_response(result):
    if 'errorType' in result:
        return {
            'isBase64Encoded': False,
            'statusCode': 400,
            'headers': {},
            'body': json.dumps(result)
        }
    else:
        return {
            'isBase64Encoded': False,
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain',
                'Content-disposition': 'attachment; filename=pub-cert.pub'
            },
            'body': result['certificate']
        }

def handle_user_request(ca_key_name, request, context):
    input_user_key = request['body']

    # Retrieve the SSH CA key
    result = get_ca_public_key(ca_key_name, 'valid_source_list')
    if result is None:
        return error_response('KeyNotFound', 'The requested CA key was not found')
    valid_source_list = [list_item['S'] for list_item in result['valid_source_list']['L']]

    # Load the user from the database
    user = get_user(input_user_key, ca_key_name)
    if user is None:
        return error_response('UserNotFound', 'The requested user was not found.')

    # Transform the data from Dynamo so it's useable
    audited_username = user['audited_username']['S']
    user_roles = [role['S'] for role in user['user_roles']['L']]

    new_request = {
        "bastion_user": audited_username,
        "bastion_user_ip": request['requestContext']['identity']['sourceIp'],
        "remote_usernames": ",".join(user_roles),
        "bastion_ips": ",".join(valid_source_list),
        "command": "",
        "public_key_to_sign": input_user_key
    }

    # Set the private CA key to the selected user CA key
    set_ca_key(ca_key_name)

    # Delegate to the original Bless lambda function
    restore_bless_cache(ca_key_name)
    result = lambda_handler_user(new_request, context)
    save_bless_cache(ca_key_name)

    return result

def handle_get_key(key_name):
    result = get_ca_public_key(key_name, 'public_key')
    if result is None:
        return error_response('KeyNotFound', 'The requested CA key was not found')
    return success_response(result['public_key']['S'])

def lambda_handler(*args, **kwargs):
    (request, context) = args
    try:
        if request['resource'] == "/ca/{key_name}" and request['httpMethod'] == "GET":
            key_name = request['pathParameters']['key_name']
            return form_response(handle_get_key(key_name))
        elif request['resource'] == "/ca/{key_name}/sign_user" and request['httpMethod'] == "POST":
            key_name = request['pathParameters']['key_name']
            return form_response(handle_user_request(key_name, request, context))
        return form_response(error_response('InvalidAction', 'An invalid action was specified'))
    except Exception as e:
        print(e)
        print(traceback.format_exc().replace("\r\n", "\r").replace("\n", "\r"))
        return form_response(error_response('UnhandledException', 'An unhandled exception was thrown'))
