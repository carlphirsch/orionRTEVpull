#!/usr/bin/env python3
"""Pull the last N System + Application events from a set of nodes, timed.

A worked example of orionRTEVpull across many hosts at once.
Reads a JSON list of targets (see --targets) and, for each node and each log,
fetches the most recent N events while timing the round trip. Prints the
events and a timing summary.

Targets JSON shape:
    [{"group": "...", "node_id": 1234, "caption": "HOST01", "os": "..."}, ...]

Credentials resolve exactly as in orionRTEVpull.py -- it shares that module's
resolve() so the two cannot drift (flags > ORION_* env vars > --env file >
prompt). The account must hold the Real-Time Event Log Viewer right, or every
pull returns HTTP 500.
"""
import argparse, getpass, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orionRTEVpull import (connect, fetch_events, ms_to_utc, load_env,  # noqa: E402
                      resolve, load_targets, OrionError, as_text, MAX_LIMIT)

# Degrade unprintable event characters instead of dying mid-print.
try:
    sys.stdout.reconfigure(errors="replace")
except (AttributeError, ValueError):
    pass


def interactive_stdin():
    """True only if we can actually prompt. stdin may be closed or replaced
    by something without isatty()."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True, help="JSON file of target nodes")
    ap.add_argument("--count", type=int, default=5, help="events per log (default 5)")
    ap.add_argument("--logs", default="System,Application",
                    help="comma-separated log names (default: System,Application)")
    ap.add_argument("--host")
    ap.add_argument("--user")
    ap.add_argument("--env", metavar="FILE")
    ap.add_argument("--insecure", action="store_true",
                    help="allow an unverified TLS certificate "
                         "(sends your password to an unauthenticated server)")
    a = ap.parse_args()

    if not 1 <= a.count <= MAX_LIMIT:
        ap.error(f"--count must be between 1 and {MAX_LIMIT}")

    try:
        envfile = load_env(a.env) if a.env else {}
    except RuntimeError as e:
        sys.exit(str(e))

    host = resolve(a.host, envfile, "ORION_HOST")
    user = resolve(a.user, envfile, "ORION_USER")
    password = resolve(None, envfile, "ORION_PASSWORD", "ORION_PASS")
    if not host or not user:
        sys.exit("need an Orion host and user (see --help)")
    if not password:
        if not interactive_stdin():
            sys.exit("no password: set ORION_PASSWORD or use --env")
        try:
            password = getpass.getpass(f"Orion password for {user}@{host}: ")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nno password entered")
        if not password:
            sys.exit("no password entered")

    logs = [x.strip() for x in a.logs.split(",") if x.strip()]
    try:
        targets = load_targets(a.targets)
    except RuntimeError as e:
        sys.exit(str(e))

    t0 = time.perf_counter()
    try:
        s, resp, authed = connect(host, user, password, insecure=a.insecure)
    except RuntimeError as e:
        sys.exit(str(e))
    login_dt = time.perf_counter() - t0
    if not authed:
        sys.exit(f"login failed (HTTP {resp.status_code}). The account must be "
                 "a LOCAL Orion account.")
    print(f"authenticated as {user} on {host}  ({login_dt:.2f}s)\n")

    timings = []
    for t in targets:
        # A targets file from an export can carry nulls; `or` rather than a
        # .get() default, which only fires on a MISSING key.
        nid = t["node_id"]
        cap = t.get("caption") or "?"
        group = t.get("group") or "?"
        print(f"=== {group}: {cap} (node {nid}) ===")
        for log in logs:
            start = time.perf_counter()
            err = None
            events = []
            try:
                j = fetch_events(s, host, nid, log=log, start=0, limit=a.count)
                events = (j.get("Events") or [])[:a.count]
            except (OrionError, TimeoutError) as e:
                err = " ".join(str(e).split())[:160]
            dt = time.perf_counter() - start
            timings.append({"group": group, "caption": cap, "log": log,
                            "seconds": round(dt, 3),
                            "events": len(events), "error": err})
            if err:
                print(f"  {log:<12} FAILED in {dt:5.2f}s: {err}")
                continue
            print(f"  {log:<12} {len(events)} events in {dt:5.2f}s")
            for e in events:
                if not isinstance(e, dict):
                    # fetch_events guarantees Events is a LIST, not that every
                    # row is an object; the module's own ingest skips these.
                    print("      (skipped a non-object row)")
                    continue
                ts = ms_to_utc(e.get("TimeGeneratedUtc"))
                tss = f"{ts:%Y-%m-%d %H:%M:%S}Z" if ts else "?"
                msg = " ".join(as_text(e.get("Message")).split())[:90]
                # Coerce every field before formatting: a format spec applied
                # to a None or a nested object raises, and this endpoint's
                # response shape is not contractual.
                code = as_text(e.get("EventCode")) or "-"
                print(f"      {tss}  id={code:<6} "
                      f"{as_text(e.get('SourceName')) or '-':.22s}  {msg}")
        print()

    ok = [x for x in timings if not x["error"]]
    print("--- timing summary ---")
    print(f"  pulls: {len(timings)}  ok: {len(ok)}  failed: {len(timings)-len(ok)}")
    if ok:
        secs = [x["seconds"] for x in ok]
        print(f"  per-pull seconds: min {min(secs):.2f}  "
              f"max {max(secs):.2f}  mean {sum(secs)/len(secs):.2f}")
    print(f"  login: {login_dt:.2f}s")
    for x in timings:
        flag = "" if not x["error"] else "  <-- FAILED"
        print(f"  {x['group']:<20} {x['caption']:<14} {x['log']:<12} "
              f"{x['seconds']:6.2f}s  ({x['events']} ev){flag}")
    # Flush here so a closed pipe is caught by the handler below rather than
    # by the interpreter's own exit flush, which prints its own error.
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
