"""Four-stage default-deny redaction pipeline for py-spy locals.

Per PLAN.md security model:
    (1) env-var-name allowlist — local whose NAME matches a known secret env-var
    (2) type-aware — Request/Response/Headers/Cookies/Session/anything-with-.headers
    (3) entropy heuristic — strings >=20 chars w/ shannon entropy >4.5
    (4) regex fallback — Telegram/Stripe/JWT/Bearer/sk-/xoxb-/ghp-/etc.

Default-deny: when any stage triggers, the value is replaced with a sentinel string.
Returns redaction count so audit log can record `redactions_applied`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

# ---- Stage 1: env-var-name allowlist --------------------------------------

# Names that are always treated as secrets, regardless of content.
SECRET_NAME_LITERALS = frozenset(
    name.lower()
    for name in [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PUBLISHABLE_KEY",
        "JWT_SECRET_KEY",
        "JWT_SECRET",
        "DATABASE_URL",
        "DB_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "APP_SECRET_KEY",
        "SECRET_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "PERPLEXITY_API_KEY",
        "ODDS_API_KEY",
        "ESPN_API_KEY",
        "INFISICAL_TOKEN",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "AUTH_TOKEN",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "BEARER_TOKEN",
        "API_KEY",
        "PRIVATE_KEY",
        "PASSWORD",
        "PASSWD",
        "PWD",
        "TOKEN",
        "SECRET",
    ]
)

# Suffix patterns — match anything *_TOKEN, *_SECRET, *_PASSWORD, *_API_KEY,
# plus camelCase variants (apiKey, authToken, stripeKey).
# We do TWO passes: a snake_case suffix match, and a camelCase tail match.
_SECRET_NAME_SUFFIX_RE = re.compile(
    r"(?:_|^)(token|secret|password|passwd|pwd|"
    r"api[_-]?key|webhook|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret|"
    r"bot[_-]?token|auth|credential[s]?|"
    r"signing[_-]?key|encryption[_-]?key|sig|nonce|otp)$",
    re.IGNORECASE,
)

# camelCase / mixedCase tail match: matches names ending in Token, Key, Secret,
# Password, Auth, Credential, Pass, Pwd. Identifies common Python+JS conventions.
_SECRET_NAME_CAMEL_RE = re.compile(
    r"(?:[a-z0-9])(Token|Key|Secret|Password|Auth|Credential[s]?|Pass|Pwd|"
    r"PrivateKey|AccessKey|ApiKey|ClientSecret|BotToken|Webhook|"
    r"SigningKey|EncryptionKey)$"
)

# DSN-shaped URLs with embedded creds: scheme://user:pass@host
_DSN_WITH_CREDS_RE = re.compile(r"://[^:/\s]+:[^@/\s]+@")


def name_is_secret(name: str) -> bool:
    """Return True if the LOCAL VARIABLE NAME indicates a secret."""
    if not name:
        return False
    n = name.lower()
    if n in SECRET_NAME_LITERALS:
        return True
    if _SECRET_NAME_SUFFIX_RE.search(n):
        return True
    # camelCase tail (use original-case for this match)
    if _SECRET_NAME_CAMEL_RE.search(name):
        return True
    return False


# ---- Stage 2: type-aware ---------------------------------------------------

# Type names (as printed by py-spy via repr/__class__.__name__) that always redact.
SENSITIVE_TYPE_NAMES = frozenset(
    [
        "Request",
        "Response",
        "Headers",
        "MutableHeaders",
        "Cookies",
        "Session",
        "ClientSession",
        "WebSocket",
        "URL",
        "Connection",
        "AsyncConnection",
        "Engine",
    ]
)

# Indicators that a repr describes an HTTP-ish object containing headers/auth.
_HEADER_INDICATOR_RE = re.compile(
    r"\b(?:authorization|cookie|set-cookie|bearer|x-api-key)\b",
    re.IGNORECASE,
)

# Pattern that looks like a Python repr of a class with .headers attribute.
# Heuristic: if the repr contains "headers=" or "Headers(", treat as sensitive.
_REPR_WITH_HEADERS_RE = re.compile(
    r"\bheaders\s*=|\bHeaders\(|\bCookies\(|\bRequest\(|\bResponse\(",
)


def repr_looks_sensitive(value_repr: str) -> bool:
    """True if the value's repr looks like an HTTP request/response/session."""
    if not value_repr:
        return False
    # Bare type-name match (e.g. starts with "<starlette.requests.Request object at ...>")
    for tname in SENSITIVE_TYPE_NAMES:
        # Match `<...{tname} object at` or `{tname}(` constructor-style repr
        if f"{tname} object at" in value_repr or f"{tname}(" in value_repr:
            return True
    if _REPR_WITH_HEADERS_RE.search(value_repr):
        return True
    if _HEADER_INDICATOR_RE.search(value_repr):
        return True
    return False


# ---- Stage 3: entropy heuristic --------------------------------------------

ENTROPY_MIN_LEN = 20
ENTROPY_THRESHOLD = 4.5


def shannon_entropy(s: str) -> float:
    """Standard Shannon entropy in bits/char."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Strings that are NOT secrets even if high entropy:
# - URLs without embedded creds
# - file paths
# - SQL fragments (start with SELECT/INSERT/UPDATE/DELETE/WITH)
_BENIGN_HIGH_ENTROPY_PREFIXES = (
    "http://", "https://", "/", "./", "../",
    "select ", "insert ", "update ", "delete ", "with ",
    "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WITH ",
)


def looks_high_entropy_secret(s: str) -> bool:
    """Stage 3: high-entropy strings that aren't obviously benign."""
    if len(s) < ENTROPY_MIN_LEN:
        return False
    # Strip surrounding quotes that py-spy might include
    candidate = s.strip().strip("'\"")
    if len(candidate) < ENTROPY_MIN_LEN:
        return False
    if any(candidate.startswith(p) for p in _BENIGN_HIGH_ENTROPY_PREFIXES):
        # Even with a benign prefix, scan the body for known secret shapes.
        # Per Grok review: 'http://example.com/#access_token=...' or
        # '/path/to/cfg?key=...' must NOT pass entropy stage just because
        # the URL prefix matches.
        if _DSN_WITH_CREDS_RE.search(candidate):
            return True
        for _label, pat in _REGEX_PATTERNS:
            if pat.search(candidate):
                return True
        # Also scan for high-entropy fragments AFTER the prefix
        # (e.g., URLs with secret query params, paths with trailing tokens).
        # Take everything after the last '=', '#', '?', '/' or whitespace and
        # check entropy of that tail.
        for sep in ("=", "#", "?"):
            if sep in candidate:
                tail = candidate.rsplit(sep, 1)[-1]
                if (
                    len(tail) >= ENTROPY_MIN_LEN
                    and shannon_entropy(tail) >= ENTROPY_THRESHOLD
                ):
                    return True
        return False
    if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
        return True
    return False


# ---- Stage 4: regex fallback for known shapes -----------------------------

# Order matters: most specific first.
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Telegram bot token — 8-10 digits, colon, 35 alphanum/_/- chars
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    # Stripe live secret keys
    ("stripe_sk_live", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("stripe_sk_test", re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b")),
    ("stripe_pk_live", re.compile(r"\bpk_live_[A-Za-z0-9]{20,}\b")),
    ("stripe_pk_test", re.compile(r"\bpk_test_[A-Za-z0-9]{20,}\b")),
    ("stripe_rk_live", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("stripe_whsec", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    # Stripe object IDs that often appear in webhook payloads
    ("stripe_obj_id", re.compile(r"\b(?:tok|cus|pi|ch|sub|seti|pm)_[A-Za-z0-9]{14,}\b")),
    # JWTs — three base64url segments separated by dots
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    # Generic Bearer tokens
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE)),
    # OpenAI / Anthropic style sk- keys
    ("sk_dash", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    # Slack
    ("slack_xoxb", re.compile(r"\bxox[bpoars]-[A-Za-z0-9-]{10,}\b")),
    # GitHub
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github_user", re.compile(r"\bghu_[A-Za-z0-9]{36}\b")),
    ("github_server", re.compile(r"\bghs_[A-Za-z0-9]{36}\b")),
    # GitLab
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    # AWS
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # Google / Firebase API keys
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    # Twilio
    ("twilio_account_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("twilio_api_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    # SendGrid
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    # PEM-encoded private keys (RSA, OpenSSH, EC, generic) — single-line scrub
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    # DSN with creds
    ("dsn_with_creds", _DSN_WITH_CREDS_RE),
    # Long hex strings that LOOK like API keys (>=32 hex chars). Catches
    # raw secret material lacking a distinct prefix. Tightened to 32 to
    # avoid matching git SHAs (which are 40 hex but typically appear in
    # commit/log contexts where redaction is desirable anyway).
    ("hex_blob_32_plus", re.compile(r"\b[A-Fa-f0-9]{40,}\b")),
]


def regex_fallback_redact(value: str) -> tuple[str, list[str]]:
    """Apply all regex patterns; return (redacted, patterns_matched)."""
    matched: list[str] = []
    out = value
    for label, pat in _REGEX_PATTERNS:
        if pat.search(out):
            matched.append(label)
            out = pat.sub(f"<redacted:{label}>", out)
    return out, matched


# ---- Top-level pipeline ---------------------------------------------------

# Sentinel strings — short, distinctive, easy to grep for in audit log.
SENTINEL_NAME = "<redacted:name>"
SENTINEL_TYPE = "<redacted:type>"
SENTINEL_ENTROPY = "<redacted:entropy>"


@dataclass
class RedactionResult:
    """Result of redacting a single (name, value_repr) pair."""

    redacted_value: str
    """The post-redaction string. Either the input unchanged, a sentinel, or a regex-substituted version."""

    triggered_stages: list[str]
    """Which stage(s) fired: any of {"name", "type", "entropy", "regex:<label>"}."""

    @property
    def was_redacted(self) -> bool:
        return bool(self.triggered_stages)


def redact_local(
    name: str,
    value_repr: str,
    *,
    extra_secret_names: Iterable[str] = (),
    extra_regex_patterns: Iterable[re.Pattern[str]] = (),
) -> RedactionResult:
    """Run the 4-stage pipeline on a single local variable.

    Args:
        name: variable name as captured by py-spy (e.g. ``request``, ``bot_token``).
        value_repr: the value's repr string from py-spy output.
        extra_secret_names: per-project secret name additions.
        extra_regex_patterns: per-project regex pattern additions.
    """
    triggered: list[str] = []
    extra_names_set = {n.lower() for n in extra_secret_names}

    # Stage 1: name allowlist
    if name_is_secret(name) or (name and name.lower() in extra_names_set):
        return RedactionResult(SENTINEL_NAME, ["name"])

    # Stage 2: type-aware
    if repr_looks_sensitive(value_repr):
        return RedactionResult(SENTINEL_TYPE, ["type"])

    # Stage 3: entropy heuristic
    if looks_high_entropy_secret(value_repr):
        triggered.append("entropy")
        # Don't return yet — also run regex so audit knows ALL signals,
        # but the displayed value is the entropy sentinel (more conservative).
        out = SENTINEL_ENTROPY
        # Still scan regex so we know what it was
        _, regex_hits = regex_fallback_redact(value_repr)
        triggered.extend(f"regex:{h}" for h in regex_hits)
        # Apply extra patterns too
        for pat in extra_regex_patterns:
            if pat.search(value_repr):
                triggered.append("regex:custom")
        return RedactionResult(out, triggered)

    # Stage 4: regex fallback
    out, regex_hits = regex_fallback_redact(value_repr)
    if regex_hits:
        triggered.extend(f"regex:{h}" for h in regex_hits)

    # Apply per-project regex extensions
    for pat in extra_regex_patterns:
        if pat.search(out):
            out = pat.sub("<redacted:custom>", out)
            triggered.append("regex:custom")

    return RedactionResult(out, triggered)


def redact_blob(text: str, *, extra_regex_patterns: Iterable[re.Pattern[str]] = ()) -> tuple[str, int]:
    """Redact secrets from a free-form blob (e.g. py-spy stack frame text without locals).

    Used for stack frame text where we don't have variable-name context.
    Returns (redacted_text, number_of_regex_matches).
    """
    out, hits = regex_fallback_redact(text)
    n = len(hits)
    for pat in extra_regex_patterns:
        if pat.search(out):
            out = pat.sub("<redacted:custom>", out)
            n += 1
    return out, n
