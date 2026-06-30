from __future__ import annotations

from oauth_cli_kit.flow import get_token
from oauth_cli_kit.models import OAuthProviderConfig, OAuthToken
from oauth_cli_kit.storage import FileTokenStorage


class _FakeResponse:
    def __init__(self, status_code: int, json_payload: dict):
        self.status_code = status_code
        self._json_payload = json_payload
        self.text = "fake"

    def json(self):
        return self._json_payload


class _FakeHttpxClient:
    """替换 httpx.Client，用于隔离网络请求。"""

    kwargs: dict | None = None

    def __init__(self, *args, **kwargs):
        self.__class__.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def post(self, url, data=None, headers=None):
        # 返回一个可解析的 refresh 响应
        return _FakeResponse(
            200,
            {
                "access_token": "new_access",
                "refresh_token": "new_refresh",
                "expires_in": 3600,
            },
        )


def test_get_token_returns_existing_when_ttl_sufficient(tmp_path, monkeypatch) -> None:
    provider = OAuthProviderConfig(
        client_id="client",
        authorize_url="https://example/auth",
        token_url="https://example/token",
        redirect_uri="http://localhost/cb",
        scope="openid",
        jwt_claim_path=None,
        account_id_claim=None,
        token_filename="t.json",
    )
    storage = FileTokenStorage(token_filename=provider.token_filename, data_dir=tmp_path, import_codex_cli=False)

    # 固定时间，避免 flake
    monkeypatch.setattr("oauth_cli_kit.flow.time.time", lambda: 1000.0)
    token = OAuthToken(access="a", refresh="r", expires=int(1000.0 * 1000 + 3600 * 1000), account_id=None)
    storage.save(token)

    got = get_token(provider=provider, storage=storage, min_ttl_seconds=60)
    assert got.access == "a"
    assert got.refresh == "r"


def test_get_token_refreshes_when_expired(tmp_path, monkeypatch) -> None:
    provider = OAuthProviderConfig(
        client_id="client",
        authorize_url="https://example/auth",
        token_url="https://example/token",
        redirect_uri="http://localhost/cb",
        scope="openid",
        jwt_claim_path=None,
        account_id_claim=None,
        token_filename="t.json",
    )
    storage = FileTokenStorage(token_filename=provider.token_filename, data_dir=tmp_path, import_codex_cli=False)

    # 让 token 过期，从而触发 refresh
    monkeypatch.setattr("oauth_cli_kit.flow.time.time", lambda: 1000.0)
    expired = OAuthToken(access="old", refresh="old_refresh", expires=int(1000.0 * 1000 - 1), account_id=None)
    storage.save(expired)

    # stub 掉 httpx.Client
    monkeypatch.setattr("oauth_cli_kit.flow.httpx.Client", _FakeHttpxClient)

    got = get_token(provider=provider, storage=storage, min_ttl_seconds=60)
    assert got.access == "new_access"
    assert got.refresh == "new_refresh"
    assert got.expires > expired.expires


def test_get_token_refresh_uses_explicit_proxy(tmp_path, monkeypatch) -> None:
    provider = OAuthProviderConfig(
        client_id="client",
        authorize_url="https://example/auth",
        token_url="https://example/token",
        redirect_uri="http://localhost/cb",
        scope="openid",
        token_filename="t.json",
    )
    storage = FileTokenStorage(token_filename=provider.token_filename, data_dir=tmp_path, import_codex_cli=False)

    monkeypatch.setattr("oauth_cli_kit.flow.time.time", lambda: 1000.0)
    storage.save(OAuthToken(access="old", refresh="old_refresh", expires=int(1000.0 * 1000 - 1), account_id=None))
    monkeypatch.setattr("oauth_cli_kit.flow.httpx.Client", _FakeHttpxClient)

    get_token(provider=provider, storage=storage, min_ttl_seconds=60, proxy="http://proxy.local:8080")

    assert _FakeHttpxClient.kwargs == {
        "timeout": 30.0,
        "proxy": "http://proxy.local:8080",
        "trust_env": False,
    }

