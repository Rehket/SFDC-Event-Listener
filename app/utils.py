from typing import Optional, Tuple
import datetime
import jwt
from jwt.exceptions import InvalidTokenError
import requests
import config

password_reset_jwt_subject = "preset"


def verify_password_reset_token(token) -> Optional[str]:
    try:
        decoded_token = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        assert decoded_token["sub"] == password_reset_jwt_subject
        return decoded_token["email"]
    except InvalidTokenError:
        return None


def jwt_login(
    consumer_id: str, username: str, private_key: str, environment: str
) -> Tuple[str, str]:
    print(private_key)
    if environment:
        if environment.lower() == "sandbox":
            endpoint = "https://test.salesforce.com"
        elif environment.lower() == "production":
            endpoint = "https://login.salesforce.com"
        else:
            raise EnvironmentError(
                f"SFDC_SANDBOX_ENVIRONMENT must be sandbox or production, got {environment}"
            )
    else:
        raise EnvironmentError(
            f"SFDC_SANDBOX_ENVIRONMENT must be sandbox or production"
        )

    jwt_payload = jwt.encode(
        {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
            "iss": consumer_id,
            "aud": endpoint,
            "sub": username,
        },
        private_key,
        algorithm="RS256",
    )

    # This makes a request againts the oath service endpoint in SFDC.
    # There are two urls, login.salesforce.com for Production and test.salesforce.com
    # for sanboxes/dev/testing environments. When using test.salesforce.com,
    # the sandbox name should be appended to the username.

    result = requests.post(
        # https://login.salesforce.com/services/oauth2/token -> PROD
        # https://test.salesforce.com/services/oauth2/token -> sandbox
        endpoint + "/services/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_payload,
        },
    )
    body = result.json()
    if result.status_code != 200:
        raise RuntimeError(f"Authentication Failed: <error: {body['error']}, description: {body['error_description']}>")
    return str(body["instance_url"]), str(body["access_token"])