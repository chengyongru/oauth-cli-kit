from __future__ import annotations

from oauth_cli_kit.flow import login_oauth_interactive
from oauth_cli_kit.models import OAuthProviderConfig, OAuthToken
from oauth_cli_kit.storage import FileTokenStorage


class _FakeServer:
    def __init__(self) -> None:
        self.shutdowns = 0
        self.closes = 0

    def shutdown(self) -> None:
        self.shutdowns += 1

    def server_close(self) -> None:
        self.closes += 1


def test_login_browser_callback_does_not_prompt_for_manual_input(tmp_path, monkeypatch) -> None:
    provider = OAuthProviderConfig(
        client_id="client",
        authorize_url="https://example/auth",
        token_url="https://example/token",
        redirect_uri="http://localhost:1455/auth/callback",
        scope="openid",
        token_filename="t.json",
    )
    storage = FileTokenStorage(token_filename=provider.token_filename, data_dir=tmp_path, import_codex_cli=False)
    exchanged: list[str] = []
    proxies: list[str | None] = []

    def start_server(state, on_code=None):
        on_code("callback-code")
        return _FakeServer(), None

    def exchange(code, verifier, provider, proxy=None):
        async def run():
            exchanged.append(code)
            proxies.append(proxy)
            return OAuthToken(access="access", refresh="refresh", expires=123)

        return run

    monkeypatch.setattr("oauth_cli_kit.flow._generate_pkce", lambda: ("verifier", "challenge"))
    monkeypatch.setattr("oauth_cli_kit.flow._create_state", lambda: "state")
    monkeypatch.setattr("oauth_cli_kit.flow._start_local_server", start_server)
    monkeypatch.setattr("oauth_cli_kit.flow._exchange_code_for_token_async", exchange)
    monkeypatch.setattr("oauth_cli_kit.flow.webbrowser.open", lambda url: True)

    token = login_oauth_interactive(
        print_fn=lambda msg: None,
        prompt_fn=lambda prompt: (_ for _ in ()).throw(AssertionError("manual prompt should not run")),
        provider=provider,
        storage=storage,
        proxy="http://proxy.local:8080",
    )

    assert token.access == "access"
    assert exchanged == ["callback-code"]
    assert proxies == ["http://proxy.local:8080"]
    assert storage.load().refresh == "refresh"


def test_login_timeout_closes_callback_server_before_manual_prompt(tmp_path, monkeypatch) -> None:
    provider = OAuthProviderConfig(
        client_id="client",
        authorize_url="https://example/auth",
        token_url="https://example/token",
        redirect_uri="http://localhost:1455/auth/callback",
        scope="openid",
        token_filename="t.json",
    )
    storage = FileTokenStorage(token_filename=provider.token_filename, data_dir=tmp_path, import_codex_cli=False)
    server = _FakeServer()
    prompt_seen_closed: list[tuple[int, int]] = []

    async def timeout(*args, **kwargs):
        raise TimeoutError

    def exchange(code, verifier, provider, proxy=None):
        async def run():
            return OAuthToken(access=code, refresh="refresh", expires=123)

        return run

    monkeypatch.setattr("oauth_cli_kit.flow._generate_pkce", lambda: ("verifier", "challenge"))
    monkeypatch.setattr("oauth_cli_kit.flow._create_state", lambda: "state")
    monkeypatch.setattr("oauth_cli_kit.flow._start_local_server", lambda state, on_code=None: (server, None))
    monkeypatch.setattr("oauth_cli_kit.flow._exchange_code_for_token_async", exchange)
    monkeypatch.setattr("oauth_cli_kit.flow.asyncio.wait_for", timeout)
    monkeypatch.setattr("oauth_cli_kit.flow.webbrowser.open", lambda url: True)

    token = login_oauth_interactive(
        print_fn=lambda msg: None,
        prompt_fn=lambda prompt: prompt_seen_closed.append((server.shutdowns, server.closes)) or "manual-code",
        provider=provider,
        storage=storage,
    )

    assert token.access == "manual-code"
    assert prompt_seen_closed == [(1, 1)]
    assert server.shutdowns == 1
    assert server.closes == 1
