#!/usr/bin/env python3
"""Smoke test for orionRTEVpull.

This is the test the README's Stability warning asks you to keep: the endpoint
it drives is a web-console feature, not a contractual API, so an Orion upgrade
can change its behavior with no notice. Run this after every upgrade and the
change fails loudly here, in one place, instead of quietly in a forensic pull.

    python3 tests/smoke_test.py                       # offline contract checks
    python3 tests/smoke_test.py --live 1234 \
        --host orion.example.com --user jsmith        # + one real pull

The offline checks need no network and no credentials: they pin the parts of
the contract your own code depends on -- the completeness verdicts, the
result shape, the rendering helpers, and input validation.

The --live check is the one that catches an upgrade. It pulls a single page
from a node you name and asserts the response is still shaped the way this
tool expects. Point it at a lab node, not something load-bearing: each run
makes the Orion server dispatch a job to that node's agent.

Exit status is 0 only if every check passes.
"""
import argparse
import datetime
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import orionRTEVpull as ow  # noqa: E402

FAILED = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        FAILED.append(name)
        # Under pytest, a recorded failure must ALSO fail the collected test.
        # The direct run deliberately never raises -- report everything, exit
        # nonzero at the end -- but pytest counts only exceptions, so without
        # this a broken tool runs green under the obvious `pytest tests/`.
        if "pytest" in sys.modules:
            raise AssertionError(name + (f" -- {detail}" if detail else ""))


# --------------------------------------------------------------------------
# Offline: the contract your code depends on.
# --------------------------------------------------------------------------
def test_result_shape():
    """SearchResult must keep both of its faces: the tuple unpack older code
    uses, and the verdicts that say whether a result is trustworthy."""
    res = ow.SearchResult(hits=[{"utc": None, "code": "7036", "src": "SCM",
                                 "user": None, "msg": "x"}],
                          scanned=5, exhausted=True)

    hits, scanned = res                       # legacy two-tuple unpack
    check("result: unpacks as (hits, scanned)", hits == res.hits and scanned == 5)
    check("result: indexes like a tuple", res[0] is res.hits and res[1] == 5)

    d = res.as_dict()
    expected = {"hits", "scanned", "exhausted", "partial", "stalled",
                "renewed", "complete"}
    check("result: as_dict has the documented keys", set(d) == expected,
          str(sorted(d)))
    check("result: as_dict agrees with the object",
          d["scanned"] == res.scanned and d["complete"] == res.complete)

    import json
    try:
        json.dumps(d, default=str)
        ok = True
    except TypeError:
        ok = False
    check("result: as_dict is JSON-serializable with default=str", ok)


def test_completeness_is_honest():
    """The verdicts are the whole reason to trust a 'no matches'. complete must
    be true only for a sweep that actually reached the end of the log."""
    cases = [
        (dict(exhausted=True), True, "clean full sweep"),
        (dict(exhausted=True, partial=True), False, "failed mid-sweep"),
        (dict(exhausted=True, stalled=True), False, "paging stalled"),
        (dict(exhausted=True, renewed=True), False, "session renewed"),
        (dict(exhausted=False), False, "page budget spent"),
    ]
    for flags, want, label in cases:
        got = ow.SearchResult(hits=[], scanned=0, **flags).complete
        check(f"verdicts: complete is {want} when {label}", got is want)


def test_rendering_helpers_never_raise():
    """Every field on the wire can be null, so the helpers must tolerate that:
    they run over data you do not control, in the middle of an incident."""
    for value in [None, "", "text", 0, 7036, [], {}, 1.5, True]:
        try:
            ow.as_text(value)
            ow.ms_to_utc(value)
            ok = True
        except BaseException as e:                       # noqa: BLE001
            ok = False
            detail = f"{type(e).__name__}: {e}"
        check(f"helpers: as_text/ms_to_utc tolerate {value!r}", ok,
              "" if ok else detail)

    check("helpers: ms_to_utc parses a serialized timestamp",
          isinstance(ow.ms_to_utc("/Date(1755200000000)/"), datetime.datetime))
    check("helpers: ms_to_utc returns None on junk",
          ow.ms_to_utc("not a date") is None)

    sparse = {"utc": None, "code": None, "src": None, "user": None, "msg": None}
    try:
        line = ow.format_hit(sparse)
        ok = isinstance(line, str)
    except BaseException as e:                           # noqa: BLE001
        ok, line = False, f"{type(e).__name__}: {e}"
    check("helpers: format_hit renders an all-null hit", ok, "" if ok else line)

    mixed = [{"utc": None}, {"utc": ow.ms_to_utc("/Date(1755200000000)/")}]
    try:
        ow.sort_hits(mixed)
        ok = True
    except BaseException:                                # noqa: BLE001
        ok = False
    check("helpers: sort_hits handles unparsed timestamps", ok)


def test_sort_hits_orders_the_timeline():
    """sort_hits is the operator's timeline: oldest first, unparseable
    timestamps last, reverse= flipping the parsed order. An unsorted return
    passed this suite when only no-raise was checked."""
    t1 = ow.ms_to_utc("/Date(1755200000000)/")
    t2 = ow.ms_to_utc("/Date(1755200001000)/")
    t3 = ow.ms_to_utc("/Date(1755200002000)/")
    hits = [{"utc": t2, "msg": "b"}, {"utc": None, "msg": "x"},
            {"utc": t3, "msg": "c"}, {"utc": t1, "msg": "a"}]
    fwd = ow.sort_hits(hits)
    check("sort: oldest first",
          [h["msg"] for h in fwd[:3]] == ["a", "b", "c"],
          str([h["msg"] for h in fwd]))
    check("sort: unparseable timestamps last", fwd[-1]["msg"] == "x")
    rev = [h["msg"] for h in ow.sort_hits(hits, reverse=True)
           if h["utc"] is not None]
    check("sort: reverse flips the parsed order", rev == ["c", "b", "a"],
          str(rev))


def test_login_page_scraping():
    """The login form is the vendor's most reshapeable surface, and the
    scraper carries bespoke armor: decoy inputs inside script or comment
    spans must not beat the real fields, and mangled markup must not take
    the parse down. Pin it offline so a refactor fails here, not at a live
    login."""
    page = """<html><head><title>Orion :: Login</title>
    <script type="text/javascript">
      var s = '<input name="__VIEWSTATE" value="DECOY-SCRIPT" />';
    </script>
    <!-- <input name="__VIEWSTATE" value="DECOY-COMMENT"> -->
    </head><body>
    <form action="/Orion/Login.aspx">
      <INPUT type="hidden" NAME="__VIEWSTATE" value="real-viewstate"/>
      <input type="hidden" name="__VIEWSTATEGENERATOR" value="gen">
      <input name="ctl00$BodyContent$Username" value="">
      <input name="broken
    </form></body></html>"""
    fields = ow._scrape_hidden_fields(page)
    check("scrape: the real hidden field wins over decoys",
          fields.get("__VIEWSTATE") == "real-viewstate", str(fields))
    check("scrape: tag/attribute casing is tolerated",
          fields.get("__VIEWSTATEGENERATOR") == "gen")
    check("scrape: an unterminated tag does not take down the parse",
          "ctl00$BodyContent$Username" in fields)
    check("login-page detector: positive on the form",
          ow._looks_like_login_page("...ctl00$BodyContent$Password..."))
    check("login-page detector: negative on JSONP",
          not ow._looks_like_login_page('cb({"Events": []})'))
    check("cryptic-error translation: a known server error is explained",
          ow._explain("Job error 0x40004 occurred") is not None)
    check("cryptic-error translation: unknown errors pass through",
          ow._explain("some novel failure") is None)


def test_input_validation():
    """Bad arguments must arrive as OrionError, not as a raw traceback from
    somewhere deep in the call stack."""
    class _Session:
        pass

    bad_calls = [
        ("limit=0", dict(limit=0)),
        ("limit above the cap", dict(limit=ow.MAX_LIMIT + 1)),
        ("start negative", dict(start=-1)),
        ("poll_timeout=0", dict(poll_timeout=0)),
        ("poll_timeout not finite", dict(poll_timeout=float("inf"))),
        ("poll_interval negative", dict(poll_interval=-1)),
    ]
    for label, kw in bad_calls:
        try:
            ow.fetch_events(_Session(), "orion.example.com", 1234, **kw)
            ok, detail = False, "no error raised"
        except ow.OrionError:
            ok, detail = True, ""
        except BaseException as e:                       # noqa: BLE001
            ok, detail = False, f"{type(e).__name__} is not an OrionError"
        check(f"validation: rejects {label}", ok, detail)

    for label, pattern in [("unbalanced group", "("), ("huge repeat", "a{4294967296}")]:
        try:
            ow.search(None, "orion.example.com", 1234, pattern)
            ok, detail = False, "no error raised"
        except ow.OrionError:
            ok, detail = True, ""
        except BaseException as e:                       # noqa: BLE001
            ok, detail = False, f"{type(e).__name__} is not an OrionError"
        check(f"validation: rejects a bad regex ({label})", ok, detail)


def test_config_parsing():
    """The credential file is parsed exactly as written -- a password is not a
    place to be clever about quoting or line endings."""
    import tempfile
    cases = [
        (b"ORION_HOST=h\nORION_USER=u\nORION_PASSWORD=p\n",
         {"ORION_HOST": "h", "ORION_USER": "u", "ORION_PASSWORD": "p"},
         "plain file"),
        (b"export ORION_HOST=h\n# a comment\n\nORION_USER=u\n",
         {"ORION_HOST": "h", "ORION_USER": "u"},
         "export prefix, comment, blank line"),
        (b"ORION_PASSWORD='p#s word'\n", {"ORION_PASSWORD": "p#s word"},
         "quoted value containing # and a space"),
        (b"ORION_PASSWORD=p=s=s\n", {"ORION_PASSWORD": "p=s=s"},
         "value containing ="),
        (b"ORION_HOST=h", {"ORION_HOST": "h"}, "no trailing newline"),
        (b"ORION_HOST=h\r\nORION_USER=u\r\n",
         {"ORION_HOST": "h", "ORION_USER": "u"}, "CRLF line endings"),
    ]
    for raw, want, label in cases:
        fd, path = tempfile.mkstemp(suffix=".env")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            got = ow.load_env(path)
        finally:
            os.unlink(path)
        check(f"config: {label}", got == want, f"got {got}")

    try:
        ow.load_env(os.path.join(tempfile.gettempdir(), "orionrtevpull-absent.env"))
        ok, detail = False, "no error raised"
    except ow.OrionError:
        ok, detail = True, ""
    except BaseException as e:                           # noqa: BLE001
        ok, detail = False, f"{type(e).__name__} is not an OrionError"
    check("config: a missing file is a clean error", ok, detail)


# --------------------------------------------------------------------------
# Live: the check that catches an Orion upgrade.
# --------------------------------------------------------------------------
def live_check(node_id, host, user, password, log, insecure):
    """One real page from one node: asserts the response still carries the
    fields this tool reads, so a changed payload fails here and not later.
    Then a second page threading the paging anchor -- server-side anchor
    handling is the one behavior the offline model deliberately cannot vouch
    for, so an upgrade that changes the window must fail HERE, not as a
    quietly short sweep. (Not collected by pytest: it takes arguments and
    drives a real node.)"""
    try:
        session, resp, authed = ow.connect(host, user, password, insecure=insecure)
    except ow.OrionError as e:
        check("live: authenticated", False, str(e))
        return
    if not authed:
        check("live: authenticated", False,
              f"HTTP {getattr(resp, 'status_code', '?')} -- the account must be "
              "a LOCAL Orion account with the viewer right")
        return
    check("live: authenticated", True, f"{user}@{host}")

    try:
        page = ow.fetch_events(session, host, node_id, log=log, limit=25)
    except ow.OrionError as e:
        check(f"live: fetched a page from node {node_id}", False, str(e))
        session.close()
        return

    check(f"live: fetched a page from node {node_id}", True)
    events = page.get("Events")
    check("live: payload carries an Events list", isinstance(events, list),
          f"got {type(events).__name__}")

    if events:
        row = events[0]
        check("live: an event row is an object", isinstance(row, dict))
        if isinstance(row, dict):
            for field in ("TimeGeneratedUtc", "EventCode", "SourceName",
                          "Message", "RecordNumber"):
                check(f"live: row still has {field}", field in row)
            check("live: the timestamp still parses",
                  ow.ms_to_utc(row.get("TimeGeneratedUtc")) is not None,
                  repr(row.get("TimeGeneratedUtc"))[:60])
    else:
        print("  NOTE  the log returned no rows; field checks skipped "
              "(try a busier log, e.g. --log System)")

    # The anchor leg. Guarded, because a quiet lab log can make it vacuous:
    # no rows or no usable RecordNumbers means nothing to anchor on, and a
    # log that fits in one over-fetched page has nothing to page into.
    anchor = max((n for n in (ow._rec_int(e) for e in (events or []))
                  if n is not None), default=0)
    total = page.get("TotalEventsCount")
    if not anchor:
        print("  NOTE  no usable RecordNumbers; the anchor check needs a "
              "busier log (try --log System)")
    elif isinstance(total, int) and total <= len(events):
        print(f"  NOTE  the whole log fits in one page ({total} rows); "
              "the anchor check has nothing to page into")
    else:
        try:
            page2 = ow.fetch_events(session, host, node_id, log=log,
                                    limit=25, start=25,
                                    last_first_record=anchor,
                                    last_total_count=total or 0)
        except ow.OrionError as e:
            check("live: an anchored second page is served", False, str(e))
            session.close()
            return
        rows2 = page2.get("Events") or []
        check("live: an anchored second page is served", True,
              f"{len(rows2)} rows")
        recs2 = [n for n in (ow._rec_int(e) for e in rows2) if n is not None]
        if recs2:
            check("live: the anchored window is pinned (no records newer "
                  "than the anchor)", max(recs2) <= anchor,
                  f"max page-2 record {max(recs2)} vs anchor {anchor}")

    session.close()


def main():
    ap = argparse.ArgumentParser(
        description="Smoke test for orionRTEVpull: offline contract checks, "
                    "plus an optional live pull that catches an Orion upgrade.")
    ap.add_argument("--live", type=int, metavar="NODEID",
                    help="also pull one page from this agent-managed NodeID")
    ap.add_argument("--log", default="System", help="log for --live (default: System)")
    ap.add_argument("--host")
    ap.add_argument("--user")
    ap.add_argument("--env", metavar="FILE",
                    help="KEY=VALUE file supplying ORION_HOST / ORION_USER / ORION_PASSWORD")
    ap.add_argument("--insecure", action="store_true",
                    help="allow an unverified TLS certificate")
    args = ap.parse_args()

    print("orionRTEVpull smoke test\n")
    print("offline contract checks:")
    for fn in (test_result_shape, test_completeness_is_honest,
               test_rendering_helpers_never_raise,
               test_sort_hits_orders_the_timeline, test_login_page_scraping,
               test_input_validation, test_config_parsing):
        # Same crash guard as the completeness runner: one crashing check
        # group must cost its own FAIL line, not every group after it.
        try:
            fn()
        except BaseException as e:                       # noqa: BLE001
            check(f"{fn.__name__} (crashed)", False, f"{type(e).__name__}: {e}")

    if args.live is not None:
        print("\nlive check:")
        try:
            envfile = ow.load_env(args.env) if args.env else {}
        except ow.OrionError as e:
            sys.exit(str(e))
        host = ow.resolve(args.host, envfile, "ORION_HOST")
        user = ow.resolve(args.user, envfile, "ORION_USER")
        password = ow.resolve(None, envfile, "ORION_PASSWORD", "ORION_PASS")
        if not host or not user:
            sys.exit("--live needs a host and user: pass --host/--user, set "
                     "ORION_HOST/ORION_USER, or supply them via --env FILE")
        if not password:
            if not sys.stdin.isatty():
                sys.exit("no password: set ORION_PASSWORD or use --env")
            password = getpass.getpass(f"Orion password for {user}@{host}: ")
        live_check(args.live, host, user, password, args.log, args.insecure)
    else:
        print("\n(no --live given: skipping the live check, which is the one "
              "that catches an Orion upgrade)")

    print()
    if FAILED:
        print(f"FAILED: {len(FAILED)} check(s): {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
