import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
import json
from os import environ
import time
from typing import FrozenSet
from urllib.parse import urlparse

import boto3
import requests

region = environ.get('AWS_REGION')
ssm_client = boto3.client('ssm', region_name=region)

cors_headers = frozenset({'access-control-request-method', 'access-control-request-headers'})
desired_headers = frozenset({*cors_headers, 'origin', 'host'})


@dataclass(frozen=True)
class ServiceConfig(object):
    service_name: str
    client_id: str
    client_secret_parameter_name: str
    parameter_name: str
    identity_field: str
    identify_with_openid: bool
    permitted_identities: FrozenSet[str]
    token_endpoint: str
    # TODO: enum?
    token_endpoint_auth_method: str

    redirect_uri: str

    # @memoized
    def get_secret(self):
        return json.loads(
            ssm_client.get_parameter(Name=self.client_secret_parameter_name,
                                     WithDecryption=True)['Parameter']['Value']
        )


services = {
    name: ServiceConfig(
        service_name=name,
        **{
            **config, "permitted_identities": frozenset(config['permitted_identities'])
        }
    )
    for name, config in json.loads(environ.get('SERVICES')).items()
}


def res(status: int, body: str, content_type='text/plain; charset=utf-8'):
    return dict(
        statusCode=status,
        headers={'content-type': content_type},
        body=body,
    )


def decode_jwt_unvalidated(jwt: str):
    start_index = jwt.index('.')
    end_index = jwt.index('.', start_index + 1)
    padding = '===' [:(4 - (end_index - start_index - 1)) % 4]
    return json.loads(base64.b64decode(jwt[start_index + 1:end_index] + padding, validate=False))


# TODO: actually set state in the browser to permit secondary authentication for providers like
# Fitbit that don't actually give you a human-readable (and thus human-configurable) user identity?
def lambda_handler(event, context):
    # Apparently the API gateway doesn't normalize header case for us?!
    headers = {
        name.lower(): value
        for name, value in event['headers'].items() if name.lower() in desired_headers
    }
    # Use 'null' because it's an actual possible value for the header and simplifies the next check.
    origin = headers.get('origin') or 'null'
    unexpected_origin = origin != 'null' and origin != headers.get('host')
    if unexpected_origin or any(header in cors_headers for header in headers):
        # This is primarily to avoid cross-origin input reflection being used in some unknown
        # malicious manner. Generally, browser CORS functionality will deny attempts to read the
        # response, but it's better safe than sorry.
        return res(403, 'Cross-origin requests not supported')

    params = event.get('queryStringParameters', {})
    error = params.get('error')
    if error is not None:
        # Reflections can be a bit scary, but with text/plain this _might_ be ok. We already try to
        # prevent some of the most likely abuse by strictly denying CORS requests.
        return res(500, f'Encountered error from service provider:\n\n{error}')
    if params.get('state'):
        return res(400, 'Malformed state')

    code = params.get('code')
    if code is None:
        return res(400, 'Missing code parameter')
    service_name = event['rawPath'][1:event['rawPath'].index('/', 1)]
    service_config = services.get(service_name)
    if service_config is None:
        return res(404, 'Not found')

    # Even though client_id isn't particularly private, we can still protect it against leaks via
    # timing attacks.
    provided_client_id = params.get('client_id')
    if (provided_client_id is not None
            and not compare_digest(service_config.client_id.encode(), provided_client_id.encode())):
        return res(403, 'Wrong client_id')

    client_secret = service_config.get_secret()["client_secret"]
    token_request = dict(
        headers={},
        data=dict(
            code=code,
            redirect_uri=service_config.redirect_uri,
            client_id=service_config.client_id,
            grant_type='authorization_code',
        )
    )
    if service_config.token_endpoint_auth_method == 'parameter':
        token_request['data']['client_secret'] = client_secret
    elif service_config.token_endpoint_auth_method == 'header':
        auth_value = base64.b64encode(f'{service_config.client_id}:{client_secret}'.encode())
        token_request['headers']['authorization'] = f'Basic {auth_value.decode()}'
    else:
        print(f'service {service_name} did not define a valid token_endpoint_auth_method')
        return res(500, 'Internal server error')

    # request_start = datetime.now(tz=timezone.utc)
    response = requests.post(service_config.token_endpoint, **token_request)
    if not response.ok:
        try:
            data = response.json()
            if data.get('error') == 'invalid_grant':
                description = data.get('error_description')
                print(
                    f'Failed to exchange code due to invalid_grant: [{response.status_code}] {description}'
                )
                return res(400, 'Provided grant not valid')
        except Exception as err:
            # From simplejson.
            if type(err).__name__ != 'JSONDecodeError':
                raise

        print(
            f'Failed to exchange code for refresh_token: [{response.status_code}] {response.text}'
        )
        return res(500, 'Failed to authenticate with service provider')

    # TODO: handle decreased scope set?
    data = response.json()
    if service_config.identify_with_openid:
        id_token = data.get('id_token')
        if id_token is None:
            return res(500, 'No identity provided')

        # We trust that this token is not forged, because we received it from Google over TLS.
        identity = decode_jwt_unvalidated(id_token)
    else:
        identity = data

    # Explicitly handle Google's terrible design where they provide the email in a field labeled
    # email even when it's not verified.
    if not identity.get('email_verified', True):
        return res(403, 'Unverified users not permitted')

    identity_value = identity.get(service_config.identity_field)
    if identity_value not in service_config.permitted_identities:
        return res(403, f'Access denied for {identity_value}')

    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        if not access_token:
            return res(500, 'No access tokens returned by service provider')
        return res(500, 'Failed to get durable access to service')
    token_type = data.get('token_type')
    if token_type != 'Bearer':
        print(f'Got token of type `{token_type}` instead of Bearer')

    # expires_at = datetime.timestamp(request_start + timedelta(seconds=data.get('expires_in', 3600)))
    param_name = service_config.parameter_name
    # TODO: will this overwrite the description?
    result = ssm_client.put_parameter(
        Name=param_name,
        Value=json.dumps(dict(refresh_token=refresh_token)),
        Type='SecureString',
        Overwrite=True,
    )
    version = result['Version']
    print(f'Saved new refresh token in {param_name} as version {version}')
    return res(200, 'Successfully stored new token')
