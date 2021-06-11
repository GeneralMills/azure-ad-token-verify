[![Python package](https://github.com/GeneralMills/azure-ad-token-verify/workflows/Python%20package/badge.svg)](https://github.com/GeneralMills/azure-ad-token-verify/actions)
[![Python](https://img.shields.io/pypi/pyversions/azure-ad-token-verify.svg)](https://pypi.python.org/pypi/azure-ad-token-verify)
# aad-token-verify
A python utility library to verify an Azure Active Directory OAuth token. Meant for resource servers serving secured API endpoints (eg FastAPI)

## Install

```bash
python3 -m pip install aad-token-verify
```

## Usage

To use stand alone, simply import the verify payload function and call.

```python
from aad_token_verify import get_verified_payload

token_verifier = AzureADTokenVerifier(tenant_id="YOUR_TENANT_ID", audience_uris=["AUDIENCE_URI"])
```

To use with FastAPI, there's some setup to get the Swagger docs to work

```python
from fastapi import Depends, FastAPI
from fastapi.openapi.models import OAuthFlowImplicit, OAuthFlows
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2

from aad_token_verify import get_verified_payload

# TODO Update these with your Tenant ID, Audience URI, and Client ID
_TENANT_ID = "ISSUER_TENANT_ID"
_AUDIENCE_URI = "https://YOUR_AUDIENCE_URI"
_AAD_CLIENT_ID = "CLIENT_ID"

oauth2_scheme = OAuth2(
    flows=OAuthFlows(
        implicit=OAuthFlowImplicit(
            authorizationUrl=f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/authorize",
            scopes={
                f"{_AUDIENCE_URI}/.default": "Custom Audience URI scope",
                "openid": "OpenID scope",
                "profile": "Profile scope",
                "email": "email scope",
            },
        )
    )
)

async def get_current_user(
    auth_header: str = Depends(oauth2_scheme),  # noqa: B008
):
    scheme, _, token = auth_header.partition(" ")
    return get_verified_payload(
        token,
        tenantId=_TENANT_ID,
        audience_uris=[_AUDIENCE_URI],
    )

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.swagger_ui_init_oauth = {
    "usePkceWithAuthorizationCodeGrant": True,
    "clientId": _AAD_CLIENT_ID,
    "scopes": [f"{_AUDIENCE_URI}.default"],
}

@app.get("/")
async def secured_endpoint(user=Depends(get_current_user)):
    return user
```

## Contributing

Feel free to submit issues and pull requests!