import os
from bless.aws_lambda import bless_lambda_common
from bless.persistence.dynamo_operations import get_ca_public_key

global_bless_caches = {}

def restore_bless_cache(key_name):
    global global_bless_caches
    bless_lambda_common.global_bless_cache = None
    if key_name in global_bless_caches:
        bless_lambda_common.global_bless_cache = global_bless_caches[key_name]

def save_bless_cache(key_name):
    global global_bless_caches
    if bless_lambda_common.global_bless_cache is not None:
        global_bless_caches[key_name] = bless_lambda_common.global_bless_cache

def set_ca_key(key_name):
    result = get_ca_public_key(key_name, 'password,private_key,validity_seconds')
    # Set env vars for key
    os.environ["ca_key_name"] = key_name
    os.environ["bless_ca_ca_private_key"] = result['private_key']['S']
    os.environ["bless_ca_default_password"] = result['password']['S']
    os.environ["bless_options_certificate_validity_after_seconds"] = \
        result['validity_seconds']['N']

