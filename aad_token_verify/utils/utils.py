from typing import Any, Dict

import requests
from cachetools import TTLCache, cached


@cached(cache=TTLCache(maxsize=16, ttl=3600))
def get_openid_config(tenant_id: str = "common") -> Dict[str, Any]:
    oidc_response = requests.get(f"https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration")
    oidc_response.raise_for_status()
    return oidc_response.json()
