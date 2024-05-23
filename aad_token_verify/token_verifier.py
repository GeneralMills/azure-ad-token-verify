from typing import Any, Dict, List

import requests
from cachetools import TTLCache, cached
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from jwt import decode, get_unverified_header
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
)

from .exceptions import AADError, AuthorizationError, TokenParseError


def get_verified_payload(
    token: str,
    tenant_id: str = "common",
    audience_uris: List[str] = None,
    oidc_version: str = None,
) -> Dict[str, Any]:
    """Gets a verified token payload

    Args:
        token (str): The token to verify
        tenant_id (str, optional): Tenant id of the issuer. Defaults to "common".
        audience_uris (List[str], optional): The audience uris of the token. Defaults to None.
        oidc_version: (str, optional):  AAD OIDC version implementation used to retrieve the well known public keys.
            The only other value accepted is "v2.0".

    Raises:
        AuthorizationError: If the token is expired
        AuthorizationError: If the audience is invalid
        AuthorizationError: If the issuer is invalid

    Returns:
        Dict[str, Any]: The verified token paylod
    """
    oidc_version = oidc_version if oidc_version == "v2.0" else ""
    kid = _get_kid_from_token_header(token)
    public_key = _get_public_key(kid, tenant_id, oidc_version)
    openid_config = _get_openid_config(tenant_id, oidc_version)
    try:
        payload = decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=audience_uris,
            issuer=openid_config.get("issuer"),
        )
    except ExpiredSignatureError:
        raise AuthorizationError("Token is expired")
    except InvalidAudienceError:
        raise AuthorizationError("Audience is invalid")
    except InvalidIssuerError:
        raise AuthorizationError("Issuer is invalid")

    return payload


def _get_kid_from_token_header(token: str) -> str:
    """Retirieves the KID from the token header

    Args:
        token (str): The token being verified

    Raises:
        TokenParseError: If unable to parse header
        TokenParseError: If no header was found
        TokenParseError: If no KID was found in the header

    Returns:
        str: The token KID
    """
    try:
        unverified_token_header = get_unverified_header(token)
    except Exception as err:  # noqa: PIE786
        raise TokenParseError("Unable to parse header") from err

    if not unverified_token_header:
        raise TokenParseError("No header found")

    if not unverified_token_header.get("kid"):
        raise TokenParseError("No kid in header found")

    return unverified_token_header.get("kid")


def _get_public_key(kid: str, tenant_id: str, oidc_version: str):
    """Retrieves the tenant public key using a token's KID

    Args:
        kid (str): The token KID
        tenant_id (str): The tenant id of the issuer

    Returns:
        [type]: The public key
    """
    try:
        x5c: List[str] = []
        # Iterate JWK keys and extract matching x5c chain
        for key in _get_jwk_keys(tenant_id, oidc_version):
            if key["kid"] == kid:
                x5c = key["x5c"]

        cert = "".join(
            [
                "-----BEGIN CERTIFICATE-----\n",
                x5c[0],
                "\n-----END CERTIFICATE-----\n",
            ]
        )
        return load_pem_x509_certificate(cert.encode(), default_backend()).public_key()
    except Exception as err:  # noqa: PIE786
        raise


@cached(cache=TTLCache(maxsize=16, ttl=3600))
def _get_jwk_keys(tenant_id: str, oidc_version: str) -> List[Dict]:
    """Retrieves the JWK keys for a specified issuer

    Args:
        tenant_id (str): The tenant id of the issuer
        oidc_version(str): OIDC version for the well known endpoint

    Raises:
        AADError: If the jwk_uri is not in the OpenID Config
        AADError: If keys are not found in jwk_keys

    Returns:
        List[Dict]: List of the jwk keys
    """
    jwks_uri = _get_openid_config(tenant_id, oidc_version).get("jwks_uri")
    if not jwks_uri:
        raise AADError("jwks_uri not in OpenID Config")

    jwks_response = requests.get(jwks_uri)
    jwks_response.raise_for_status()
    jwk_keys = jwks_response.json()

    if not jwk_keys or not jwk_keys.get("keys"):
        raise AADError("keys not found in jwk_keys")

    return jwk_keys.get("keys")


@cached(cache=TTLCache(maxsize=16, ttl=3600))
def _get_openid_config(tenant_id: str, oidc_version: str) -> Dict[str, Any]:
    """Retrieves the OpenID config for a specified issuer

    Args:
        tenant_id (str): The tenant id of the issuer
        oidc_version(str): OIDC version for the well known endpoint

    Returns:
        Dict[str, Any]: The OpenID config
    """
    oidc_response = requests.get(
        f"https://login.microsoftonline.com/{tenant_id}/{oidc_version}/.well-known/openid-configuration"
    )
    oidc_response.raise_for_status()
    return oidc_response.json()
