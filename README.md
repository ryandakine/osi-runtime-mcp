# osi-runtime-mcp

> Live, read-only runtime introspection for Docker'd Python services, exposed
> as an MCP server so Claude Code (or any MCP-compatible agent) can debug
> production without local repro.

I built this in roughly an hour while debugging a "zero bets for 13 days"
incident on one of my own platforms. I needed something that let an AI agent
see what a live celery worker was actually doing without me copying log lines
into chat. It worked, so I'm leaving it here in case it's useful.

The first thing it caught — within minutes of being installed — was a docker
healthcheck that had been silently broken for 23 hours (`pgrep` missing from
the slim Python base image). One of those bugs you only notice when you
actually look at every container's status, and you only do *that* when an AI
agent does it for you.

## Tools

| Tool | What it does |
|---|---|
| `list_services(project=None)` | Discover containers labeled `osi.runtime.introspect=allow` |
| `dump_python_stack(service, workers="first", with_locals=False, ...)` | `py-spy dump` against child Python PIDs, redacted |
| `read_metrics(service)` | Scrape `/metrics`, parse Prometheus exposition |
| `health_check_ptrace(service)` | Verify `py-spy` can attach (catches missing caps / yama config) |

All tools refuse to touch services that aren't explicitly opted in via Docker
labels. `with_locals=True` requires a *separate* opt-in label. Every call is
appended to an audit log.

## Security model

Designed for the prompt-injection threat model — the agent is trusted but
fallible (could exfiltrate values to its provider). Layers:

1. **Allowlist via Docker labels.** No `osi.runtime.introspect=allow` label =
   service is invisible. No `osi.runtime.allow_locals=true` = `with_locals`
   refuses even if the agent asks.
2. **4-stage default-deny redaction** on every local variable returned:
   - env-var-name allowlist (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`,
     plus camelCase variants)
   - type-aware (FastAPI `Request`, anything with `.headers`/`.cookies`)
   - entropy heuristic (≥20 chars, Shannon ≥4.5 → redacted)
   - regex fallback for ~15 known token shapes (Stripe, Telegram, JWT, AWS,
     Google AIza, Slack xoxb, GitHub ghp_, GitLab glpat-, SendGrid SG.,
     Twilio AC/SK, PEM private keys, …)
3. **Subprocess hygiene.** Every input validated against `^[a-z0-9_-]+$`
   *before* it reaches `subprocess.run` (list-form, `shell=False`).
4. **256 KB hard byte budget** per response, 10s timeout, max 50 frames per
   thread, max 16 threads per worker. Defaults: one worker per service,
   no locals.
5. **Audit log** at `/var/log/osi-runtime-mcp/audit-YYYY-MM-DD.jsonl` —
   `chmod 600`, append-only, daily rotated.

## Prerequisites for a target service

Add to your service's compose entry:

```yaml
services:
  backend:
    cap_add: [SYS_PTRACE]                    # py-spy needs this
    labels:
      osi.runtime.introspect: "allow"
      osi.runtime.allow_locals: "true"       # opt-in per service
      osi.runtime.language: "python"
      osi.runtime.project: "myapp"
```

And `pip install 'py-spy>=0.3.14,<0.4'` in your image.

## Install

```bash
git clone https://github.com/ryandakine/osi-runtime-mcp
cd osi-runtime-mcp
uv sync --extra test
uv run pytest                                # 166 tests, ~0.6s
```

## Run (stdio)

```bash
uv run osi-runtime-mcp
```

## Register with Claude Code

Append to `~/.claude.json` under `mcpServers`:

```json
"osi-runtime": {
  "command": "uv",
  "args": ["run", "--directory", "/path/to/osi-runtime-mcp", "osi-runtime-mcp"]
}
```

Restart Claude Code. You'll have `mcp__osi-runtime__list_services`,
`dump_python_stack`, `read_metrics`, and `health_check_ptrace` in tool calls.

## What it isn't

- Not Lightrun. No bytecode rewriting, no logpoints, no IDE plugin.
  `dump_python_stack` covers ~80% of debug-via-introspection at 5% of the
  build complexity.
- Not multi-language. Python only. JVM/.NET/Node coverage isn't planned —
  `read_metrics` is the answer for any service that exposes `/metrics`.
- Not multi-tenant. Stdio transport assumes the agent runs on the same box
  as the services. HTTP transport with auth is sketched but not built —
  open an issue if you need it.
- Not a substitute for centralized logs. Pair it with Loki + Promtail (or
  whatever you have) for log queries. This is for *what's the process doing
  right now*.

## License

MIT — do whatever you want with it.
