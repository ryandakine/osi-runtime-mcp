# osi-runtime-mcp

Live, read-only runtime introspection for Docker'd Python services, exposed as
an MCP server. Lets Claude Code (or any MCP-compatible agent) inspect a running
process without ssh-ing in or rebuilding the image. `py-spy` for stack dumps,
Prometheus scraping for metrics, Docker labels for access control, 4-stage
secret redaction on every byte returned, audit log on every call.

Python 3.11+. MIT.

## Why

Debugging Python in production usually means: tail logs, ssh in, run `py-spy`
by hand, copy lines back into the agent. This collapses that loop. The agent
calls `dump_python_stack("celery-worker")` and gets a redacted JSON snapshot —
no shell access, no image rebuild, no extra ports.

The first thing it caught — minutes after install — was a Docker healthcheck
that had been silently broken for 23 hours (`pgrep` missing from a slim Python
base). The kind of bug you only notice when something actually checks every
container's status.

## Quickstart

**1. Label the target service** (compose entry):

```yaml
services:
  backend:
    cap_add: [SYS_PTRACE]                    # py-spy needs this
    labels:
      osi.runtime.introspect: "allow"
      osi.runtime.allow_locals: "true"       # opt-in per service for with_locals
      osi.runtime.language: "python"
      osi.runtime.project: "myapp"
```

Add `pip install 'py-spy>=0.3.14,<0.4'` to the image.

**2. Install and run the server**:

```bash
git clone https://github.com/ryandakine/osi-runtime-mcp
cd osi-runtime-mcp
uv sync --extra test
uv run pytest          # 166 tests, ~0.6s
uv run osi-runtime-mcp # stdio
```

**3. Register with Claude Code** — append to `~/.claude.json` under
`mcpServers`:

```json
"osi-runtime": {
  "command": "uv",
  "args": ["run", "--directory", "/path/to/osi-runtime-mcp", "osi-runtime-mcp"]
}
```

Restart Claude Code. Tools appear as `mcp__osi-runtime__list_services`,
`dump_python_stack`, `read_metrics`, `health_check_ptrace`.

## Tools

| Tool | Purpose | Params |
|---|---|---|
| `list_services` | Discover containers labeled `osi.runtime.introspect=allow` | `project?` |
| `health_check_ptrace` | Verify `py-spy` can attach (catches missing caps / yama config). Run before first `dump_python_stack` on a new service. | `service`, `project?` |
| `dump_python_stack` | `py-spy dump --json` against child Python PIDs, redacted, 256KB-bounded. PID 1 (`infisical run`) is skipped. | `service`, `workers="first"\|"all"\|N`, `with_locals=False`, `unsafe_locals=False`, `project?` |
| `read_metrics` | Scrape `/metrics`, parse Prometheus exposition. Requires a host-published port. | `service`, `format="json"\|"prometheus"`, `project?` |

All `service` / `project` values must match `^[a-z0-9_-]+$` and resolve to a
labeled container.

## Security

Designed for the prompt-injection threat model — the agent is trusted but
fallible (it could exfiltrate values to its provider). Layers:

1. **Allowlist via Docker labels.** No `osi.runtime.introspect=allow` = service
   is invisible. No `osi.runtime.allow_locals=true` = `with_locals` refuses
   even if the agent asks.
2. **4-stage default-deny redaction** on every local repr returned:
   - env-var-name allowlist (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`,
     plus camelCase variants)
   - type-aware (FastAPI `Request`, anything with `.headers` / `.cookies`)
   - entropy heuristic (>=20 chars, Shannon >=4.5 -> redacted)
   - regex fallback for ~15 known token shapes (Stripe, Telegram, JWT, AWS,
     Google AIza, Slack xoxb, GitHub ghp_, GitLab glpat-, SendGrid SG.,
     Twilio AC/SK, PEM private keys, ...)
3. **Subprocess hygiene.** Every input validated against `^[a-z0-9_-]+$`
   *before* it reaches `subprocess.run` (list-form, `shell=False`).
4. **Hard limits.** 256KB byte budget per response, 10s tool timeout, 50
   frames per thread, 16 threads per worker. Defaults: one worker per service,
   no locals.
5. **Audit log** at `/var/log/osi-runtime-mcp/audit-YYYY-MM-DD.jsonl` —
   `chmod 600`, `chattr +a` where supported, daily rotated. Override with
   `OSI_RUNTIME_AUDIT_DIR`. Every tool call logged with args, result size,
   redaction count, and any errors.

`unsafe_locals=true` bypasses the type-aware guard but still applies the other
three stages. Reserve for offline debugging.

## Limitations

- **Read-only.** No mutation, no breakpoints, no bytecode rewriting. Not
  Lightrun. `dump_python_stack` covers ~80% of debug-via-introspection at 5%
  of the build complexity.
- **Python only.** JVM / .NET / Node coverage isn't planned. Use `read_metrics`
  for any service that exposes `/metrics`.
- **py-spy 0.3.x supports Python <=3.11.** 3.12+ targets need py-spy 0.4.x
  when it ships.
- **Single-host.** Stdio transport assumes the agent runs on the same box as
  the services. HTTP transport with bearer auth is sketched in
  `osi-runtime.example.yaml` but not built — open an issue if you need it.
- **Not a log replacement.** Pair with Loki + Promtail (or whatever) for log
  history. This answers *what is the process doing right now*.

## License

MIT. See `LICENSE`.
