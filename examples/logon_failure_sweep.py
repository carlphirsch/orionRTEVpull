#!/usr/bin/env python3
"""Timed sweep: search each target node's live Security log for logon failures.

A worked example of orionRTEVpull's search() path (regex over Message/SourceName
while paging back through the live log, deduped on RecordNumber). Each node's
search is wall-clock timed around the network work only.

Targets JSON shape (same file as multi_node_timing.py):
    [{"group": "...", "node_id": 1234, "caption": "HOST01", "os": "..."}, ...]

The default pattern catches the classic Windows logon-failure phrasings:
4625 ("An account failed to log on"), legacy "Logon Failure", and Kerberos
4771 ("Kerberos pre-authentication failed").

HEADS UP -- the Security log is where logon failures live, so that is this
example's default, but on many nodes the Security log does not read under the
inherited node credential: the agent job stays pending and then ends in a WMI
timeout (ErrorCode 0x40004) after roughly 85 seconds. That is a property of the
endpoint, not a bug here. Such nodes are reported individually and the sweep
continues, so budget ~85s per failing node. If every node fails this way, the
inherited credential cannot read Security on this estate -- try --log System
with a pattern suited to it, or supply a credential that can.
"""
import argparse, getpass, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orionRTEVpull import (connect, search, load_env, resolve,  # noqa: E402
                      load_targets, sort_hits, OrionError, as_text, MAX_LIMIT)


def completeness(res):
    """One short tag naming why a result is not the whole story.

    A logon-failure sweep that truncated is the case that matters most: "0
    matches" from a partial sweep is not evidence that nothing happened, so
    every line this example prints says which kind of answer it is.
    """
    if res.complete:
        return "complete"
    why = []
    if res.partial:
        why.append("failed mid-sweep")
    if res.stalled:
        why.append("paging stalled")
    if res.renewed:
        why.append("session renewed")
    if not res.exhausted and not why:
        why.append("page budget spent")
    return "FLOOR (" + ", ".join(why) + ")"


def interactive_stdin():
    """True only if we can actually prompt. stdin may be closed or replaced
    by something without isatty()."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False

# Degrade unprintable event characters instead of dying mid-print.
try:
    sys.stdout.reconfigure(errors="replace")
except (AttributeError, ValueError):
    pass

DEFAULT_PATTERN = "failed to log on|logon failure|pre-authentication failed"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True, help="JSON file of target nodes")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN)
    ap.add_argument("--log", default="Security")
    ap.add_argument("--pages", type=int, default=6, help="max pages per node")
    ap.add_argument("--limit", type=int, default=200, help="rows per page")
    ap.add_argument("--show", type=int, default=3, help="matches to print per node")
    ap.add_argument("--host")
    ap.add_argument("--user")
    ap.add_argument("--env", metavar="FILE")
    ap.add_argument("--insecure", action="store_true",
                    help="allow an unverified TLS certificate "
                         "(sends your password to an unauthenticated server)")
    a = ap.parse_args()

    if a.pages < 1:
        ap.error("--pages must be at least 1")
    if not 1 <= a.limit <= MAX_LIMIT:
        ap.error(f"--limit must be between 1 and {MAX_LIMIT}")
    if a.show < 0:
        ap.error("--show cannot be negative")

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
        sys.exit(f"login failed (HTTP {resp.status_code})")
    print(f"authenticated as {user} on {host}  ({login_dt:.2f}s)")
    print(f"pattern: {a.pattern!r}  log: {a.log}  depth: {a.pages}x{a.limit}\n")

    results = []
    for t in targets:
        # A targets file generated from an export can carry nulls; `or` rather
        # than a .get() default, which only fires on a MISSING key.
        nid = t["node_id"]
        cap = t.get("caption") or "?"
        group = t.get("group") or "?"
        start = time.perf_counter()
        err, res = None, None
        try:
            res = search(s, host, nid, a.pattern, log=a.log,
                         max_pages=a.pages, limit=a.limit)
        except (OrionError, TimeoutError) as e:
            err = " ".join(str(e).split())[:160]
        dt = time.perf_counter() - start
        results.append({
            "group": group, "caption": cap, "seconds": round(dt, 2),
            "scanned": res.scanned if res else 0,
            "matches": len(res.hits) if res else 0,
            "complete": bool(res and res.complete),
            "verdict": completeness(res) if res else "failed",
            "error": err})
        if err:
            print(f"=== {group}: {cap} (node {nid}) FAILED in {dt:.2f}s: {err}\n")
            continue
        print(f"=== {group}: {cap} (node {nid}) — scanned {res.scanned} events, "
              f"{len(res.hits)} logon-failure matches in {dt:.2f}s "
              f"[{completeness(res)}]")
        if not res.complete and not res.hits:
            print("      no matches, but this sweep did not finish — absence "
                  "of evidence here is NOT evidence of absence")
        for h in sort_hits(res.hits, reverse=True)[:a.show]:
            tss = f"{h['utc']:%Y-%m-%d %H:%M:%S}Z" if h.get("utc") else "?"
            code = as_text(h.get("code")) or "-"
            print(f"      {tss}  id={code}  {as_text(h.get('msg'))[:100]}")
        print()

    ok = [r for r in results if not r["error"]]
    floors = [r for r in ok if not r["complete"]]
    print("--- timing summary (per-node search, network work only) ---")
    print(f"  login: {login_dt:.2f}s   nodes: {len(results)}  ok: {len(ok)}  "
          f"failed: {len(results)-len(ok)}")
    if ok:
        secs = [r["seconds"] for r in ok]
        print(f"  per-node seconds: min {min(secs):.2f}  max {max(secs):.2f}  "
              f"mean {sum(secs)/len(secs):.2f}")
    for r in results:
        if r["error"]:
            flag = "  <-- FAILED"
        elif not r["complete"]:
            flag = f"  <-- {r['verdict']}"
        else:
            flag = ""
        print(f"  {r['group']:<20} {r['caption']:<14} {r['seconds']:7.2f}s  "
              f"scanned {r['scanned']:>5}  matches {r['matches']:>4}{flag}")
    if floors:
        print(f"\n  {len(floors)} of {len(ok)} successful nodes returned a FLOOR, "
              "not a complete sweep. Raise --pages, or re-run those nodes, "
              "before reporting an absence of logon failures.")
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
