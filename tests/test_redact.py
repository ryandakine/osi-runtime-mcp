"""Tests for the 4-stage redaction pipeline.

Coverage:
    - Stage 1: env-var-name allowlist (literal + suffix patterns)
    - Stage 2: type-aware (Request/Response/Headers reprs)
    - Stage 3: entropy heuristic (>=20 char high-entropy strings)
    - Stage 4: regex fallback (Telegram/Stripe/JWT/Bearer/sk-/etc.)
    - Whole-corpus assertion: no secret substring survives any fixture
    - Negative tests: normal values pass through
"""

from __future__ import annotations

import re

import pytest

from osi_runtime_mcp.redact import (
    SENTINEL_ENTROPY,
    SENTINEL_NAME,
    SENTINEL_TYPE,
    name_is_secret,
    redact_blob,
    redact_local,
    repr_looks_sensitive,
    shannon_entropy,
)
from tests.fixtures.redact_corpus import FIXTURES


# ---- Stage 1: env-var-name allowlist --------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "TELEGRAM_BOT_TOKEN",
        "telegram_bot_token",
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "JWT_SECRET_KEY",
        "API_KEY",
        "PASSWORD",
        "GITHUB_TOKEN",
        "my_custom_TOKEN",
        "internal_api_key",
        "client_secret",
        "user_password",
    ],
)
def test_name_is_secret_positive(name):
    assert name_is_secret(name), f"{name!r} should be detected as a secret name"


@pytest.mark.parametrize(
    "name",
    [
        "user_id",
        "request",
        "limit",
        "count",
        "amount_cents",
        "filename",
        "model",
        "branch",
        "query_str",
    ],
)
def test_name_is_secret_negative(name):
    assert not name_is_secret(name), f"{name!r} should NOT be flagged"


def test_stage1_redacts_telegram_bot_token_via_name():
    """The Telegram bot token's REGEX shape is unique, but if a project uses a
    short/oddly-formatted token, the name allowlist must still catch it."""
    r = redact_local(
        "TELEGRAM_BOT_TOKEN",
        '"weirdshortvalue"',  # doesn't match regex
    )
    assert r.was_redacted
    assert r.redacted_value == SENTINEL_NAME
    assert "name" in r.triggered_stages


def test_stage1_redacts_database_url_via_name():
    r = redact_local("DATABASE_URL", '"postgresql://user:pwd@db/x"')
    assert r.redacted_value == SENTINEL_NAME


# ---- Stage 2: type-aware --------------------------------------------------


@pytest.mark.parametrize(
    "value_repr",
    [
        "<starlette.requests.Request object at 0x7f1234>",
        "<fastapi.responses.JSONResponse object at 0x7f1234>",
        "<starlette.datastructures.Headers object at 0x7f1234>",
        "Headers({'authorization': 'Bearer xxx'})",
        "<sqlalchemy.engine.base.Connection object at 0x7f5678>",
        "Cookies({'session': 'abc'})",
    ],
)
def test_repr_looks_sensitive_positive(value_repr):
    assert repr_looks_sensitive(value_repr)


@pytest.mark.parametrize(
    "value_repr",
    [
        "42",
        '"normal string value"',
        "[1, 2, 3]",
        "{'count': 5}",
        "None",
    ],
)
def test_repr_looks_sensitive_negative(value_repr):
    assert not repr_looks_sensitive(value_repr)


def test_stage2_redacts_request_object():
    r = redact_local("req", "<starlette.requests.Request object at 0x7f1234>")
    assert r.redacted_value == SENTINEL_TYPE
    assert "type" in r.triggered_stages


def test_stage2_authorization_header_caught():
    """Even if name is benign, the repr containing Authorization gets redacted."""
    r = redact_local(
        "headers_dict",
        "Headers({'authorization': 'Bearer xxx', 'host': 'localhost'})",
    )
    assert r.redacted_value == SENTINEL_TYPE


# ---- Stage 3: entropy heuristic -------------------------------------------


def test_shannon_entropy_low():
    assert shannon_entropy("aaaaaaaaaaaa") < 1.0


def test_shannon_entropy_high():
    assert shannon_entropy("aB3xY9pQ7nM2vZ8kL5jH") > 4.0


def test_stage3_high_entropy_string_redacted():
    """A long high-entropy string with a TRULY benign name still gets redacted by stage 3."""
    # Use a name that doesn't trip the name allowlist or suffix regex
    r = redact_local("opaque_blob", '"aB3xY9pQ7nM2vZ8kL5jH4fG7tR1wE6sD"')
    assert r.was_redacted
    assert r.redacted_value == SENTINEL_ENTROPY
    assert "entropy" in r.triggered_stages


def test_stage3_normal_string_passes():
    r = redact_local("user_message", '"Hello world, how are you?"')
    assert not r.was_redacted


def test_stage3_short_random_passes():
    """Short strings, even random, don't trigger entropy stage (only >=20)."""
    r = redact_local("opaque_id", '"aB3xY9pQ"')
    assert not r.was_redacted


def test_stage3_url_with_creds_caught():
    """https://user:pass@... should redact even though it starts with http://."""
    r = redact_local(
        "endpoint",
        '"https://api_user:supersecret123@api.example.com/v1/data"',
    )
    assert r.was_redacted


# ---- Stage 4: regex fallback ----------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        # Telegram (real format — exactly 35 chars after colon)
        "1234567890:AAHabcdefghijklmnopqrstuvwxyz123456",
        # Stripe
        "sk_test_FAKEFAKEFAKEFAKEFAKEFAKEX",
        "pk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        "whsec_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        # JWT
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567",
        # OpenAI/Anthropic style
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
        # Slack
        "xoxb-AAAAAAAAAAA-AAAAAAAAAAA",
        # GitHub
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        # GitLab
        "glpat-aBcDeFgHiJkLmNoPqRsT",
        # AWS
        "AKIAIOSFODNN7EXAMPLE",
        # Google API key (Firebase, Maps, etc.)
        "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK",
        # Twilio
        "ACfeedfacefeedfacefeedfacefeedface",
        "SKfeedfacefeedfacefeedfacefeedface",
        # SendGrid
        "SG.FAKEFAKEFAKEFAKE.FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        # Long hex blob (raw API key without prefix)
        "deadbeefcafe0123456789abcdef0123456789abcdef",
    ],
)
def test_regex_fallback_catches_known_shapes(secret):
    """Even with a benign name, the regex layer must catch known secret shapes."""
    blob = f'message="user pasted: {secret} into chat"'
    r = redact_local("benign_name", blob)
    # Either redacted-as-entropy or regex matched — both acceptable.
    # The non-negotiable: the original secret substring is NOT in the output.
    assert secret not in r.redacted_value, (
        f"secret leaked through redaction: {secret!r} in {r.redacted_value!r}"
    )


def test_redact_blob_preserves_normal_text():
    text = "INFO: user_42 logged in from 10.0.0.5"
    out, n = redact_blob(text)
    assert n == 0
    assert out == text


def test_url_with_secret_query_param_caught():
    """Grok review (b): URL prefixes can't whitelist embedded secrets."""
    # URL prefix is benign, but the access_token in the fragment is high-entropy
    val = '"http://example.com/callback#access_token=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123"'
    r = redact_local("redirect_url", val)
    assert r.was_redacted, f"URL with embedded secret should be redacted: {r}"


def test_path_with_appended_token_caught():
    """Path prefix can't whitelist embedded JWT."""
    val = '"/api/v1/proxy?key=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sigsigsigsig"'
    r = redact_local("path", val)
    assert r.was_redacted


def test_camelcase_name_authToken_redacted():
    """Grok review (c): camelCase variants must trip stage 1."""
    r = redact_local("authToken", '"plainvalue"')
    assert r.was_redacted
    r2 = redact_local("apiKey", '"plain"')
    assert r2.was_redacted
    r3 = redact_local("stripeKey", '"plain"')
    assert r3.was_redacted


def test_pem_private_key_redacted():
    pem = (
        '"-----BEGIN RSA PRIVATE KEY-----\\n'
        'MIIEpAIBAAKCAQEA1234567890abcdefghij\\n'
        '-----END RSA PRIVATE KEY-----"'
    )
    r = redact_local("key_pem", pem)
    assert r.was_redacted
    assert "MIIEpAIBAAKCAQEA" not in r.redacted_value


def test_redact_blob_redacts_telegram():
    # Real Telegram bot token format: 8-10 digits, colon, 35 chars [A-Za-z0-9_-]
    token35 = "AAHabcdefghijklmnopqrstuvwxyz123456"  # 35 chars exactly
    assert len(token35) == 35
    blob = f"Sending message via bot 1234567890:{token35} to chat"
    out, n = redact_blob(blob)
    assert n >= 1
    assert "1234567890:AAH" not in out


# ---- Whole-corpus assertion (the main acceptance test) ------------------


@pytest.mark.parametrize(
    "fixture", FIXTURES, ids=lambda f: f[0]
)
def test_corpus_no_secret_substring_survives(fixture):
    """For every realistic frame fixture, no secret substring may appear in any
    locals' final redacted_value, AND no high-entropy string >=20 chars survives."""
    name, locals_, banned_substrings = fixture
    survivors_text: list[str] = []
    for local_name, value_repr in locals_:
        r = redact_local(local_name, value_repr)
        survivors_text.append(r.redacted_value)
    joined = "\n".join(survivors_text)

    for banned in banned_substrings:
        assert banned not in joined, (
            f"[{name}] secret substring {banned!r} survived redaction:\n{joined}"
        )

    # Additional: no string >=20 chars with high entropy may survive raw.
    # We allow sentinels to pass; we look at quoted string contents.
    high_entropy_re = re.compile(r'"([^"]{20,})"')
    for surv in survivors_text:
        for m in high_entropy_re.finditer(surv):
            content = m.group(1)
            ent = shannon_entropy(content)
            # Allow benign URLs/paths that pass the entropy stage's whitelist.
            # The hard rule: if it's high-entropy AND not a path/URL, fail.
            if ent >= 4.5 and not any(
                content.startswith(p)
                for p in (
                    "http://",
                    "https://",
                    "/",
                    "./",
                    "../",
                )
            ):
                pytest.fail(
                    f"[{name}] high-entropy unredacted string survived: "
                    f"ent={ent:.2f} content={content!r}"
                )


# ---- Direct: env-var-name allowlist catches Telegram via NAME -----------


def test_env_var_name_allowlist_catches_telegram_token_by_name():
    """PLAN.md test: 'Frame contains bot_token=...; assert redacted'
    Note: bot_token matches both name (suffix _token) AND regex shape.
    We assert it's redacted regardless of which stage fires."""
    r = redact_local("bot_token", '"1234567890:AAHshort"')
    assert r.was_redacted


def test_database_url_with_embedded_password_redacted():
    """PLAN.md test: 'hunter2 not in output'."""
    r = redact_local(
        "db_url",
        '"postgresql+asyncpg://betting:hunter2@db/betting_v2"',
    )
    assert r.was_redacted
    assert "hunter2" not in r.redacted_value
