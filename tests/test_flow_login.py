from __future__ import annotations

from oauth_cli_kit.flow import login_oauth_interactive
from oauth_cli_kit.models import OAuthProviderConfig, OAuthToken
from oauth_cli_kit.storage import FileTokenStorage


class _FakeServer:
    def shutdown(self) -> None:
        pass

    def server_close(self) -> None:
        pass


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
