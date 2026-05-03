"""Realistic py-spy local-frame fixtures from production-shaped code paths.

Each fixture is a list of (name, value_repr) tuples mirroring py-spy's
JSON output format. The redaction tests assert that every value containing
a secret survives the pipeline as a sentinel, AND that no high-entropy
string >=20 chars escapes raw.

Fixture inventory:
    1. fastapi_handler_with_request — Request object + auth header
    2. celery_stripe_webhook — Stripe webhook payload with sk_test + whsec
    3. sqlalchemy_session_with_dsn — DATABASE_URL with embedded password
    4. telegram_send_frame — bot_token + chat_id + message
    5. jwt_verify_frame — Bearer + decoded JWT
    6. anthropic_call_frame — sk-ant-... + prompt text
    7. github_token_frame — ghp_... in subprocess args
    8. multi_secret_frame — kitchen sink, every shape at once
"""

from __future__ import annotations

# Each entry: (fixture_name, list of (local_name, value_repr), set_of_secret_substrings_that_must_not_appear)
FIXTURES: list[tuple[str, list[tuple[str, str]], list[str]]] = [
    (
        "fastapi_handler_with_request",
        [
            ("self", '<v2.api.routes.predictions.PredictionsRouter object at 0x7f1234>'),
            ("request", '<starlette.requests.Request object at 0x7f5678>'),
            ("user_id", '"user_42"'),
            (
                "authorization_header",
                '"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
            ),
            ("limit", "20"),
        ],
        [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT body
            "Bearer eyJ",  # Bearer prefix
        ],
    ),
    (
        "celery_stripe_webhook",
        [
            (
                "stripe_secret",
                '"sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"',
            ),
            ("webhook_signature", '"whsec_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"'),
            ("event_id", '"evt_1NABCDxyz"'),
            ("customer_id", '"cus_NABCDEFGHIJK"'),
            ("payment_intent_id", '"pi_3MABCDxyzABCDEFGHIJKLMNO"'),
            ("amount_cents", "10000"),
        ],
        [
            "sk_test_FAKEFAKEFAKEFAKEFAKE",
            "whsec_FAKEFAKEFAKEFAKE",
        ],
    ),
    (
        "sqlalchemy_session_with_dsn",
        [
            ("session", "<sqlalchemy.orm.session.Session object at 0x7fabc>"),
            (
                "DATABASE_URL",
                '"postgresql+asyncpg://betting:hunter2supersecretpassword@db:5432/betting_v2"',
            ),
            ("query_str", '"SELECT id, name FROM users WHERE active = true"'),
            ("limit", "100"),
        ],
        ["hunter2supersecretpassword"],
    ),
    (
        "telegram_send_frame",
        [
            (
                # 8-10 digit prefix, colon, exactly 35 [A-Za-z0-9_-] chars
                "bot_token",
                '"1234567890:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
            ),
            ("chat_id", '"-1001234567890"'),
            ("message", '"Tonight\'s lock: KC -3.5 (-110)"'),
            ("parse_mode", '"MarkdownV2"'),
        ],
        ["1234567890:AAH"],
    ),
    (
        "jwt_verify_frame",
        [
            (
                "token",
                '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signature1234567890abcdef"',
            ),
            (
                "secret_key",
                '"a1b2c3d4e5f6789012345678901234567890abcdefghij"',
            ),
            ("algorithm", '"HS256"'),
        ],
        [
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9",
            "a1b2c3d4e5f6789012345678901234567890",
        ],
    ),
    (
        "anthropic_call_frame",
        [
            (
                "api_key",
                '"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890Ab"',
            ),
            ("model", '"claude-3-7-sonnet-20250219"'),
            ("prompt", '"Summarize today\'s NFL injury reports."'),
            ("max_tokens", "1024"),
        ],
        ["sk-ant-api03-AbCdEfGhIjKl"],
    ),
    (
        "github_token_frame",
        [
            ("repo", '"acme/runtime-mcp"'),
            (
                "GITHUB_TOKEN",
                '"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"',
            ),
            ("branch", '"main"'),
        ],
        ["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ"],
    ),
    (
        "multi_secret_kitchen_sink",
        [
            (
                "tg_token",
                # 35 chars after the colon
                '"1234567890:AAHabcdefghijklmnopqrstuvwxyz123456"',
            ),
            ("stripe_pk", '"pk_test_FAKEFAKEFAKEFAKEFAKEAAAAAAAAAAAAAAA"'),
            ("aws_key", '"AKIAIOSFODNN7EXAMPLE"'),
            ("slack_bot", '"xoxb-AAAAAAAAAAA-AAAAAAAAAAA"'),
            ("gitlab_token", '"glpat-aBcDeFgHiJkLmNoPqRsT"'),
            (
                "redis_url",
                '"redis://default:rediscachepassword99@redis:6379/0"',
            ),
            ("normal_count", "42"),
            ("flag", "True"),
        ],
        [
            "1234567890:AAHabcdef",
            "pk_test_FAKEFAKEFAKEFAKEFAKE",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-AAAAAAAAAAA-AAAAAAAAAAA",
            "glpat-aBcDeFgHiJk",
            "rediscachepassword99",
        ],
    ),
]
