"""Live acceptance test — call each tool against a running labeled Python stack.

Defaults to inspecting whichever introspectable container has osi.runtime.language=python.
Override with --service NAME to target a specific compose service.

Run with:
    uv run python scripts/live_acceptance.py [--service backend]
"""

from __future__ import annotations

import argparse
import sys

from osi_runtime_mcp.tools.dump_python_stack import dump_python_stack
from osi_runtime_mcp.tools.health_check_ptrace import health_check_ptrace
from osi_runtime_mcp.tools.list_services import list_services


def green(s: str) -> str:
    return f"\033[32m{s}\033[0m"


def red(s: str) -> str:
    return f"\033[31m{s}\033[0m"


def step(name: str) -> None:
    print(f"\n=== {name} ===")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--service", default=None,
                    help="compose service name to dump (default: first python service found)")
    args = ap.parse_args()

    failures: list[str] = []

    # ---- 1. list_services ----
    step("1. list_services()")
    resp = list_services()
    print(f"  found {len(resp.services)} introspectable services:")
    for s in resp.services:
        print(f"    - {s.container_name} (project={s.osi_project} lang={s.language})")
    python_services = [s for s in resp.services if s.language == "python"]
    if not python_services:
        failures.append("list_services: no python services found")
        print(red("  FAIL: no python services labeled introspectable"))
        print(red("  hint: add osi.runtime.introspect=allow + osi.runtime.language=python labels to a Python container"))
        return 1
    print(green(f"  PASS — {len(python_services)} python services labeled"))

    target = args.service or python_services[0].service
    print(f"\n  Using service='{target}' for the rest of the checks.")

    # ---- 2. health_check_ptrace(target) ----
    step(f"2. health_check_ptrace(service={target!r})")
    health = health_check_ptrace(service=target)
    print(f"  ptrace_ok={health.ptrace_ok} child_pid={health.child_pid_found} "
          f"comm={health.child_comm} version={health.py_spy_version}")
    if health.error:
        print(f"  error: {health.error}")
    if health.hint:
        print(f"  hint: {health.hint}")
    if not health.ptrace_ok:
        failures.append(f"health_check_ptrace: ptrace_ok=False")
        print(red("  FAIL"))
    else:
        print(green("  PASS"))

    # ---- 3. dump_python_stack(target) — no locals ----
    step(f"3. dump_python_stack(service={target!r}) — no locals")
    dump = dump_python_stack(service=target)
    print(f"  workers={len(dump.workers)} duration_ms={dump.duration_ms}")
    if not dump.workers:
        failures.append("dump_python_stack: no workers returned")
        print(red("  FAIL: no workers"))
    else:
        w = dump.workers[0]
        print(f"  worker pid={w.pid} threads={len(w.threads)}")
        if w.error:
            failures.append(f"dump_python_stack: worker error {w.error}")
            print(red(f"  FAIL: worker error: {w.error}"))
        elif not w.threads:
            failures.append("dump_python_stack: no threads")
            print(red("  FAIL: no threads"))
        else:
            print(green(f"  PASS — {sum(len(t.frames) for t in w.threads)} frames captured"))

    # ---- 4. dump_python_stack(target) — with_locals=True ----
    step(f"4. dump_python_stack(service={target!r}, with_locals=True)")
    dump_l = dump_python_stack(service=target, with_locals=True)
    print(f"  workers={len(dump_l.workers)} redactions={dump_l.redactions_applied}")
    if not dump_l.workers or not dump_l.workers[0].threads:
        failures.append("dump_python_stack with_locals: no threads")
        print(red("  FAIL"))
    else:
        # Search for any local that's redacted
        redacted_names: list[str] = []
        for t in dump_l.workers[0].threads:
            for fr in t.frames:
                if fr.locals:
                    for loc in fr.locals:
                        if loc.redacted:
                            redacted_names.append(f"{fr.name}/{loc.name}")
        if redacted_names:
            print(f"  redacted locals seen: {redacted_names[:5]}")
            print(green(f"  PASS — redaction pipeline triggered "
                        f"on {len(redacted_names)} locals"))
        else:
            # Even if nothing was redacted, this is OK as long as no secret leaked.
            # We do a sanity scan: dump all local reprs and check no obvious secret patterns.
            payload = dump_l.model_dump_json()
            from osi_runtime_mcp.redact import _REGEX_PATTERNS
            leaks = []
            for label, pat in _REGEX_PATTERNS:
                if pat.search(payload):
                    leaks.append(label)
            if leaks:
                failures.append(f"dump_python_stack with_locals: secret patterns leaked: {leaks}")
                print(red(f"  FAIL — leaks: {leaks}"))
            else:
                print(green("  PASS — no secrets leaked even though no redactions fired "
                            "(idle worker with no sensitive locals)"))

    # ---- 5. Allowlist refusal — request a non-introspectable service ----
    step("5. dump_python_stack(service='nginx') — must refuse (no label)")
    try:
        dump_python_stack(service="nginx")
        failures.append("dump_python_stack: should have refused unlabeled 'nginx'")
        print(red("  FAIL: did not refuse"))
    except Exception as e:
        print(f"  refused with: {type(e).__name__}: {e}")
        print(green("  PASS"))

    # ---- 6. Validation — injection attempt ----
    step("6. dump_python_stack(service='evil; rm -rf /') — must reject at validation")
    try:
        dump_python_stack(service="evil; rm -rf /")
        failures.append("dump_python_stack: should have rejected injection")
        print(red("  FAIL"))
    except Exception as e:
        print(f"  rejected with: {type(e).__name__}: {e}")
        print(green("  PASS"))

    # ---- summary ----
    print()
    if failures:
        print(red(f"FAIL — {len(failures)} failures:"))
        for f in failures:
            print(red(f"  - {f}"))
        return 1
    print(green(f"All acceptance checks passed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
