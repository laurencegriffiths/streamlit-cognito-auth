from typing import Dict, Any, Tuple

import pycognito # type: ignore
from pycognito import Cognito

from .exceptions import TokenVerificationException
import logging

def verify_access_token(pool_id, app_client_id, region, access_token,refresh_token) -> Tuple[Dict[str, Any], pycognito.UserObj]:
    logger= logging.getLogger(__name__)
    if not access_token:
        raise TokenVerificationException("Empty access token")

    u = Cognito(pool_id, app_client_id, user_pool_region=region,refresh_token=refresh_token)
    try:
        if refresh_token:
            logger.info(f"old access token {access_token}")
            u.renew_access_token()
            logger.info(f"Renewed access token: {u.access_token}")
        claims = u.verify_token(u.access_token, "access_token", "access")
        user = u.get_user()
        return claims, user
    except pycognito.exceptions.TokenVerificationException as e:
        raise TokenVerificationException(e)

