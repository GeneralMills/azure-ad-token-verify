import requests
from typing import Any, List, Dict
from cachetools import cached, TTLCache

@cached(cache=TTLCache(maxsize=16, ttl=3600))
def get_openid_config(tenant_id: str = "common") -> Dict[str, Any]:
    oidc_response = requests.get(f"https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration")
    oidc_response.raise_for_status()
    return oidc_response.json()