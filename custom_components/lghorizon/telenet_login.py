"""Telenet username/password login (fork addition, see FORK.md).

Telenet (country code ``be-nl``) only supports refresh-token auth in the
upstream integration. This module runs Telenet's real SSO login (OAuth2
authorization code + PKCE against Okta at secure.telenet.be) with a plain
username and password and returns a refresh token, which the config flow then
uses exactly like a pasted refresh token. The password is never stored.

Ported from ChristoVanDurme/woelf-control4-telenet-tvbox
(tools/python-tests/scripts/credential_login.py). Never log credentials,
session tokens, codes or refresh tokens here.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp
import voluptuous as vol
from yarl import URL

from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession

_LOGGER = logging.getLogger(__name__)

TELENET_COUNTRY_CODE = "be-nl"
API_URL = "https://spark-prod-be.gnp.cloud.telenet.tv"
SSO_AUTHORIZATION_PATH = "/auth-service/v1/sso/authorization"
FINAL_REDIRECT_HOST = "www.telenet.tv"
MAX_REDIRECTS = 20
TIMEOUT = aiohttp.ClientTimeout(total=30)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT}
REFRESH_TOKEN_KEY = "refresh_token"  # same value as const.CONF_REFRESH_TOKEN


class TelenetLoginError(Exception):
    """Telenet login failed for a technical reason."""


class TelenetInvalidAuth(TelenetLoginError):
    """Telenet rejected the username or password."""


def telenet_password_schema(country_code: str) -> dict:
    """Extra optional password field for the credentials/reauth forms."""
    if country_code != TELENET_COUNTRY_CODE:
        return {}
    return {vol.Optional(CONF_PASSWORD): str}


async def async_apply_telenet_login(
    hass: HomeAssistant, country_code: str, username: str, data: dict[str, Any]
) -> None:
    """If a Telenet password was entered (and no refresh token), log in.

    Replaces the password in ``data`` by the refresh token it yields, so the
    rest of the upstream flow only ever sees (and stores) a refresh token.
    """
    if country_code != TELENET_COUNTRY_CODE:
        return
    password = data.get(CONF_PASSWORD)
    data[CONF_PASSWORD] = None
    if not password or data.get(REFRESH_TOKEN_KEY):
        return
    data[REFRESH_TOKEN_KEY] = await async_telenet_refresh_token(
        hass, username, password
    )


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


async def async_telenet_refresh_token(
    hass: HomeAssistant, username: str, password: str
) -> str:
    """Run the Telenet SSO login chain and return a refresh token."""
    # Own session (own cookie jar) per login, closed afterwards.
    session = async_create_clientsession(hass, auto_cleanup=False)
    try:
        return await _login(session, username, password)
    except aiohttp.ClientError as err:
        raise TelenetLoginError(f"Connection error: {type(err).__name__}") from err
    finally:
        await session.close()


async def _login(session: aiohttp.ClientSession, username: str, password: str) -> str:
    code_verifier, code_challenge = _pkce_pair()

    # 1. Telenet backend hands out an Okta authorize URL (our PKCE challenge
    #    is threaded through to the final outer-client authorize hop).
    async with session.get(
        f"{API_URL}{SSO_AUTHORIZATION_PATH}",
        params={"code_challenge": code_challenge, "code_challenge_method": "S256"},
        headers=HEADERS,
        timeout=TIMEOUT,
    ) as resp:
        resp.raise_for_status()
        step1 = await resp.json(content_type=None)
    authorization_uri = step1["authorizationUri"]
    validity_token = step1["validityToken"]

    # 2. Follow redirects to Okta's hosted authorize endpoint.
    async with session.get(
        authorization_uri, headers=HEADERS, timeout=TIMEOUT
    ) as resp:
        okta_authorize_url = str(resp.url)
    parsed = urlparse(okta_authorize_url)
    okta_base = f"{parsed.scheme}://{parsed.netloc}"

    # 3. Okta classic Authentication API.
    async with session.post(
        f"{okta_base}/api/v1/authn",
        json={"username": username, "password": password},
        headers={**HEADERS, "Accept": "application/json"},
        timeout=TIMEOUT,
    ) as resp:
        authn = await resp.json(content_type=None)
        authn_status = resp.status
    if authn_status == 401 or authn.get("errorCode") == "E0000004":
        raise TelenetInvalidAuth("Telenet rejected the username or password")
    if authn.get("status") != "SUCCESS":
        # Only the status name, never the body (it holds a stateToken).
        raise TelenetLoginError(
            f"Okta authentication not completed: {authn.get('status') or authn_status}"
        )
    session_token = authn["sessionToken"]

    # 4. Redeem the session token and walk the redirect chain manually until
    #    www.telenet.tv/sso/login_success.html?code=... is reached.
    sep = "&" if "?" in okta_authorize_url else "?"
    url = f"{okta_authorize_url}{sep}sessionToken={session_token}"
    final_code = None
    for _ in range(MAX_REDIRECTS):
        async with session.get(
            URL(url, encoded=True),
            allow_redirects=False,
            headers=HEADERS,
            timeout=TIMEOUT,
        ) as resp:
            location = resp.headers.get("Location")
        if not location:
            break
        url = urljoin(url, location)
        loc = urlparse(url)
        query = parse_qs(loc.query)
        if "error" in query:
            raise TelenetLoginError(f"Login redirect error: {query['error'][0]}")
        if "code" in query and loc.netloc == FINAL_REDIRECT_HOST:
            final_code = query["code"][0]
            break
    if not final_code:
        raise TelenetLoginError("No authorization code at the end of the login redirects")

    # 5. Exchange the code (+ PKCE verifier) for household tokens.
    async with session.post(
        f"{API_URL}{SSO_AUTHORIZATION_PATH}",
        json={
            "authorizationGrant": {
                "authorizationCode": final_code,
                "validityToken": validity_token,
                "codeVerifier": code_verifier,
            }
        },
        headers=HEADERS,
        timeout=TIMEOUT,
    ) as resp:
        resp.raise_for_status()
        result = await resp.json(content_type=None)
    if not result.get("refreshToken") or result.get("householdId") in (
        None,
        "anonymous",
    ):
        raise TelenetLoginError("Login did not return a Telenet household session")
    _LOGGER.debug("Telenet login succeeded")
    return result["refreshToken"]
