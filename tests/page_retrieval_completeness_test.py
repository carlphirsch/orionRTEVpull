#!/usr/bin/env python3
"""Page-retrieval completeness tests for orionRTEVpull.

The smoke test checks that the tool still talks to a real Orion correctly.
This checks the part you cannot see from outside: that a multi-page sweep
returns every event exactly once, and that the completeness verdicts tell the
truth. Those verdicts are the whole reason you can trust a "no matches" -- so
they deserve a test that does not need an Orion at all.

    python3 tests/page_retrieval_completeness_test.py

No network, no credentials. A deterministic model of the server stands in for
the endpoint, reproducing the two behaviors the paging logic has to survive:

  * the server over-fetches -- it returns several times the page size you ask
    for, so consecutive pages OVERLAP heavily and arrive full of duplicates;
  * an empty page is the only end-of-data signal.

Failure models beside it produce the recoverable faults the hardening exists
for -- a still-pending job, a mid-sweep cookie expiry, the response-size
ceiling, rows without RecordNumbers, the auto-limit resize -- so the
completeness verdicts are exercised end-to-end, not only as constructor
flags.

THE CENTRAL PROPERTY is metamorphic: for one fixed log, the ANSWER must not
depend on how you ask for it. Sweeping the same log at different page sizes,
page budgets, or with --deep on or off must return the identical set of
records. A client that de-duplicates wrongly, or stops early on a run of
duplicate pages, breaks that property immediately -- which is exactly the
class of bug that would otherwise show up as a quietly short forensic result.

A test like this is only worth having if it can actually fail, so
test_the_oracle_has_teeth() sabotages the ingest path on purpose and asserts
the checks catch it. If that test ever passes silently, the rest of this file
is decorative.

Exit status is 0 only if every check passes.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import orionRTEVpull as ow  # noqa: E402

FAILED = []
OVERFETCH = 4          # the server returns ~4x the page size asked for


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


class ModelLog:
    """A fixed log of `size` events, served the way the endpoint serves them.

    Records are numbered `size` down to 1, newest first, which is the order the
    viewer returns. A request for offset `start` yields OVERFETCH x limit rows
    from that offset, so pages overlap and repeat; past the end it yields an
    empty page, which is the client's only legitimate stop signal.

    Every request is recorded so the tests can assert how the client paged, not
    just what it ended up with.
    """

    def __init__(self, size, message="Service Control Manager stopped"):
        self.size = size
        self.message = message
        self.requests = []                      # (start, limit, anchor)

    def _row(self, rec):
        return {"RecordNumber": rec,
                "TimeGeneratedUtc": f"/Date({1_700_000_000_000 + rec * 1000})/",
                "EventCode": 7036,
                "SourceName": "Service Control Manager",
                "User": None,
                "ComputerName": "HOST01",
                "Message": f"{self.message} (record {rec})"}

    def fetch_once(self, s, host, node_id, log, cred, levels, start, limit,
                   tz_offset, sources, last_first_record=0, last_total_count=0,
                   timeout=90, deadline=None):
        self.requests.append((start, limit, last_first_record))
        rows = [self._row(self.size - i)
                for i in range(start, min(start + OVERFETCH * limit, self.size))]
        return {"JobPollingStatus": 4, "TotalEventsCount": self.size,
                "Events": rows}


class PendingThenServeModel(ModelLog):
    """Answer the first `pending` requests with a still-running job and no
    events -- exactly what a real dispatch returns before the agent reports --
    then serve normally. A client that treats that first empty page as final
    reports a false 'complete, no matches'."""

    def __init__(self, size, pending=3):
        super().__init__(size)
        self.pending = pending

    def fetch_once(self, s, host, node_id, log, cred, levels, start, limit,
                   tz_offset, sources, last_first_record=0, last_total_count=0,
                   timeout=90, deadline=None):
        if self.pending > 0:
            self.pending -= 1
            self.requests.append((start, limit, last_first_record))
            return {"JobPollingStatus": 1, "TotalEventsCount": self.size,
                    "Events": []}
        return ModelLog.fetch_once(self, s, host, node_id, log, cred, levels,
                                   start, limit, tz_offset, sources,
                                   last_first_record, last_total_count,
                                   timeout, deadline)


class ExpireOnceModel(ModelLog):
    """Raise SessionExpired on exactly the `raise_on`-th request (1-based),
    then serve normally -- a cookie expiring mid-sweep."""

    def __init__(self, size, raise_on=2):
        super().__init__(size)
        self.calls = 0
        self.raise_on = raise_on

    def fetch_once(self, s, host, node_id, log, cred, levels, start, limit,
                   tz_offset, sources, last_first_record=0, last_total_count=0,
                   timeout=90, deadline=None):
        self.calls += 1
        if self.calls == self.raise_on:
            raise ow.SessionExpired("modelled cookie expiry")
        return ModelLog.fetch_once(self, s, host, node_id, log, cred, levels,
                                   start, limit, tz_offset, sources,
                                   last_first_record, last_total_count,
                                   timeout, deadline)


class TooLargeModel(ModelLog):
    """Refuse to serialize while the requested limit exceeds `cap_limit` (the
    size ceiling). serve_first=N switches to a second mode: serve the first N
    requests, then refuse forever regardless of limit."""

    def __init__(self, size, cap_limit=60, serve_first=None):
        super().__init__(size)
        self.cap_limit = cap_limit
        self.serve_first = serve_first
        self.calls = 0

    def fetch_once(self, s, host, node_id, log, cred, levels, start, limit,
                   tz_offset, sources, last_first_record=0, last_total_count=0,
                   timeout=90, deadline=None):
        self.calls += 1
        refuse = (self.calls > self.serve_first if self.serve_first is not None
                  else limit > self.cap_limit)
        if refuse:
            self.requests.append((start, limit, last_first_record))
            raise ow.ResponseTooLarge("modelled size ceiling")
        return ModelLog.fetch_once(self, s, host, node_id, log, cred, levels,
                                   start, limit, tz_offset, sources,
                                   last_first_record, last_total_count,
                                   timeout, deadline)


class NoRecordNumberModel(ModelLog):
    """Serve rows that carry no RecordNumber at all -- a broken provider --
    so the paging anchor can never advance."""

    def _row(self, rec):
        row = ModelLog._row(self, rec)
        del row["RecordNumber"]
        return row


def sweep(model, pattern=r"Service Control", **kw):
    """Run a real search() against the model and return (result, records seen)."""
    class Session:
        def __init__(self):
            self.reauth_count = 0

        def reauth(self, deadline=None):        # lets --deep re-dispatch
            self.reauth_count += 1
            return True

        def close(self):
            pass

    original = ow._fetch_once
    ow._fetch_once = model.fetch_once
    try:
        res = ow.search(Session(), "orion.example.com", 1234, pattern, **kw)
    finally:
        ow._fetch_once = original
    seen = {int(m.group(1))
            for m in (re.search(r"record (\d+)", h["msg"] or "") for h in res.hits)
            if m}
    return res, seen


# --------------------------------------------------------------------------
# The central property: how you ask must not change the answer.
# --------------------------------------------------------------------------
def test_configuration_cannot_change_the_answer():
    size = 500
    baseline, baseline_records = sweep(ModelLog(size), limit=50, max_pages=100)
    check("baseline sweep reaches the whole log",
          baseline.complete and len(baseline_records) == size,
          f"complete={baseline.complete} records={len(baseline_records)}/{size}")

    variants = [
        ("limit=25",           dict(limit=25,  max_pages=100)),
        ("limit=200",          dict(limit=200, max_pages=100)),
        ("limit=800",          dict(limit=800, max_pages=100)),
        ("generous budget",    dict(limit=50,  max_pages=400)),
        ("deep mode",          dict(limit=50,  max_pages=100, deep=True)),
        ("deep + small pages", dict(limit=25,  max_pages=100, deep=True)),
    ]
    for label, kw in variants:
        res, records = sweep(ModelLog(size), **kw)
        check(f"same answer with {label}",
              records == baseline_records,
              f"{len(records)} records vs {len(baseline_records)}"
              + ("" if records == baseline_records
                 else f"; missing {sorted(baseline_records - records)[:5]}"))


def test_every_record_is_returned_exactly_once():
    """Pages overlap by design, so this is really a de-duplication test."""
    size = 300
    model = ModelLog(size)
    res, records = sweep(model, limit=50, max_pages=100)

    check("every record in the log was found", records == set(range(1, size + 1)),
          f"{len(records)}/{size}")
    check("no record was counted twice", res.scanned == size,
          f"scanned={res.scanned} distinct={len(records)}")
    check("hits are a subset of what was scanned", len(res.hits) <= res.scanned)

    rows_served = sum(min(start + OVERFETCH * lim, size) - start
                      for start, lim, _ in model.requests if start < size)
    check("the model really did serve duplicates (else this proves nothing)",
          rows_served > size, f"{rows_served} rows served for {size} records")


def test_the_paging_anchor_matches_what_was_seen():
    """The client threads the newest RecordNumber it has seen back to the
    server as the paging anchor. Pinned at zero, paging walls out early on a
    busy log, so assert the actual contract -- the anchor equals the newest
    record seen so far -- rather than merely that it never decreases, which a
    permanently-zero anchor would also satisfy.

    NOTE ON SCOPE: this model pages purely by offset and ignores the anchor it
    is sent, so this asserts what the CLIENT sends, not that a real server
    honors it. Anchor semantics are the one part of the endpoint worth
    confirming against a live node."""
    size = 400
    model = ModelLog(size)
    sweep(model, limit=50, max_pages=100)
    anchors = [anchor for _, _, anchor in model.requests]

    check("the first request opens with no anchor", anchors[0] == 0, str(anchors[:4]))
    check("every later request anchors on the newest record seen",
          all(a == size for a in anchors[1:]),
          f"expected {size}, got {sorted(set(anchors[1:]))}")
    check("the anchor never goes backwards",
          all(b >= a for a, b in zip(anchors, anchors[1:])))


# --------------------------------------------------------------------------
# The verdicts have to be honest in both directions.
# --------------------------------------------------------------------------
def test_a_truncated_sweep_reports_a_floor():
    size = 1000
    res, records = sweep(ModelLog(size), limit=25, max_pages=3)   # too few pages
    check("a spent page budget is not reported as complete", not res.complete,
          f"complete={res.complete}")
    check("a spent page budget is not reported as exhausted", not res.exhausted)
    check("the partial result is a genuine subset", 0 < len(records) < size,
          f"{len(records)}/{size}")


def test_a_finished_sweep_reports_complete():
    for size in (1, 7, 60, 250):
        res, records = sweep(ModelLog(size), limit=20, max_pages=200)
        check(f"log of {size}: reached the end and says so",
              res.complete and len(records) == size,
              f"complete={res.complete} records={len(records)}/{size}")


def test_an_empty_log_is_complete_not_a_floor():
    res, records = sweep(ModelLog(0))
    check("an empty log is complete with no hits",
          res.complete and not records and res.scanned == 0,
          f"complete={res.complete} scanned={res.scanned}")


def test_sweeps_are_idempotent():
    a, a_records = sweep(ModelLog(200), limit=50, max_pages=100)
    b, b_records = sweep(ModelLog(200), limit=50, max_pages=100)
    check("two identical sweeps agree",
          a_records == b_records and a.scanned == b.scanned
          and a.complete == b.complete)


def test_a_pattern_selects_without_losing_coverage():
    """Matching fewer events must not mean scanning fewer: `scanned` is the
    coverage figure the completeness verdict describes, not the hit count."""
    size = 120
    model = ModelLog(size)
    res, _ = sweep(model, pattern=r"record (?:1|2)\b", limit=30, max_pages=100)
    check("a narrow pattern still scans the whole log", res.scanned == size,
          f"scanned={res.scanned}/{size}")
    check("a narrow pattern returns fewer hits than events scanned",
          len(res.hits) < res.scanned, f"hits={len(res.hits)}")
    check("a narrow pattern still reports complete", res.complete)


# --------------------------------------------------------------------------
# The recoverable faults: the sweeps the hardening exists for. Each model
# produces one, so the verdicts are earned end-to-end, not hand-set.
# --------------------------------------------------------------------------
def test_pending_pages_are_polled_not_reported_empty():
    """A real first dispatch returns a still-running job with no events;
    fetch_events' docstring promises that is never surfaced as an empty log.
    This is the offline pin for that promise -- a mutation that returned the
    pending page as final walked through both suites before it existed."""
    size = 200
    model = PendingThenServeModel(size, pending=3)
    res, records = sweep(model, limit=50, max_pages=100, poll_interval=0.01)
    check("pending pages are re-polled, not returned",
          len(model.requests) > 3 and records == set(range(1, size + 1)),
          f"{len(model.requests)} requests, {len(records)}/{size} records")
    check("the re-polls repeat the same request",
          len({(s, lim) for s, lim, _ in model.requests[:4]}) == 1,
          str(model.requests[:4]))
    check("a polled-through sweep still reports complete",
          res.complete and res.scanned == size,
          f"complete={res.complete} scanned={res.scanned}")


def test_an_all_pending_job_is_never_an_empty_log():
    """If the job NEVER goes terminal, the honest outcome is a timeout error;
    anything else would mimic an empty log."""
    model = PendingThenServeModel(0, pending=10 ** 9)
    try:
        sweep(model, limit=50, max_pages=3, poll_interval=0.01,
              poll_timeout=0.1)
        ok, detail = False, "no error raised"
    except TimeoutError:                    # RtevTimeout is a TimeoutError
        ok, detail = True, ""
    except BaseException as e:                           # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    check("a never-finishing job raises rather than returning empty", ok,
          detail)


def test_a_mid_sweep_renewal_never_claims_complete():
    """A cookie expiring mid-sweep is recovered silently, but the renewal
    restarts the real server's paging window -- so the verdict must carry
    renewed=True and refuse completeness, even when (as in this model) every
    record was still reached."""
    size = 300
    model = ExpireOnceModel(size, raise_on=2)
    res, records = sweep(model, limit=50, max_pages=100)
    check("the sweep survives the expiry and keeps the data",
          records == set(range(1, size + 1)), f"{len(records)}/{size}")
    check("renewed is flagged", res.renewed is True)
    check("a renewed sweep never claims complete", res.complete is False)


def test_too_large_responses_downsize_and_finish_complete():
    """The size ceiling halves the limit on a fresh dispatch and re-walks;
    dedupe absorbs the re-walk, the verdict stays honest -- and the tool's
    own re-dispatch must NOT be flagged as a renewal."""
    size = 400
    model = TooLargeModel(size, cap_limit=60)
    res, records = sweep(model, limit=200, max_pages=100)
    limits = [lim for _, lim, _ in model.requests]
    check("the limit was halved until it fit", limits[:3] == [200, 100, 50],
          str(limits[:5]))
    check("the downsized sweep reaches the whole log",
          res.complete and records == set(range(1, size + 1)),
          f"complete={res.complete} records={len(records)}/{size}")
    check("a self-inflicted re-dispatch is not flagged as renewed",
          res.renewed is False)


def test_persistent_too_large_degrades_to_partial_or_raises():
    """Refusals that survive downsizing: keep gathered data as PARTIAL when
    there is any; raise when there was never anything to keep."""
    size = 300
    res, records = sweep(TooLargeModel(size, serve_first=1),
                         limit=50, max_pages=100)
    check("data gathered before the refusals is kept as PARTIAL",
          res.partial and 0 < len(records) < size and not res.complete,
          f"partial={res.partial} records={len(records)}/{size}")

    try:
        sweep(TooLargeModel(size, serve_first=0), limit=50, max_pages=100)
        ok, detail = False, "no error raised"
    except ow.ResponseTooLarge:
        ok, detail = True, ""
    except BaseException as e:                           # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    check("a first-page refusal that cannot downsize raises", ok, detail)


def test_rows_without_recordnumbers_stall_but_keep_data():
    """Rows with no usable RecordNumber pin the anchor: paging cannot
    advance, so the sweep must stop, keep the rows it was given, and say
    INCOMPLETE -- not walk the same window forever."""
    size = 120
    model = NoRecordNumberModel(size)
    res, records = sweep(model, limit=50, max_pages=100)
    check("the stalled page's rows are kept",
          res.scanned == size and len(records) == size,
          f"scanned={res.scanned} records={len(records)}/{size}")
    check("stalled is flagged and complete is refused",
          res.stalled is True and res.complete is False)
    check("the stall stopped paging (no useless re-walk)",
          len(model.requests) == 1, f"{len(model.requests)} requests")


def test_auto_limit_resizes_from_measured_rows():
    """auto_limit sizes the page from the first page's measured bytes-per-row
    and restarts on a fresh dispatch. These lean modelled rows push the limit
    UP past the manual ceiling; the sweep must still be complete, correct,
    and must not flag its own re-dispatch as a renewal."""
    size = 500
    model = ModelLog(size)
    res, records = sweep(model, limit=200, max_pages=100, auto_limit=True)
    limits = [lim for _, lim, _ in model.requests]
    check("the first page ran at the requested limit", limits[0] == 200,
          str(limits[:3]))
    check("auto-limit raised the page size from measured rows",
          any(lim > ow.MAX_LIMIT for lim in limits[1:]),
          str(sorted(set(limits))))
    check("the resized sweep is still complete and correct",
          res.complete and records == set(range(1, size + 1))
          and not res.renewed,
          f"complete={res.complete} records={len(records)}/{size}")


# --------------------------------------------------------------------------
# If this file cannot fail, it is worthless. Prove that it can.
# --------------------------------------------------------------------------
def test_the_oracle_has_teeth():
    size = 300
    original = ow._ingest

    def dropping_ingest(events, rx, state):
        """Silently discard one row in seven -- the exact failure this file
        exists to catch, and the one that would otherwise look like a short
        but plausible forensic result."""
        return original([e for i, e in enumerate(events) if i % 7], rx, state)

    ow._ingest = dropping_ingest
    try:
        res, records = sweep(ModelLog(size), limit=50, max_pages=100)
        caught = (records != set(range(1, size + 1))) or (res.scanned != size)
    finally:
        ow._ingest = original

    check("sabotage is detected (dropping 1 row in 7)", caught,
          f"records={len(records)}/{size} scanned={res.scanned}")

    res, records = sweep(ModelLog(size), limit=50, max_pages=100)
    check("and the checks pass again once the sabotage is removed",
          records == set(range(1, size + 1)) and res.scanned == size)


def main():
    print("orionRTEVpull sweep tests (modelled server, no network)\n")
    for fn in (test_the_oracle_has_teeth,
               test_configuration_cannot_change_the_answer,
               test_every_record_is_returned_exactly_once,
               test_the_paging_anchor_matches_what_was_seen,
               test_a_truncated_sweep_reports_a_floor,
               test_a_finished_sweep_reports_complete,
               test_an_empty_log_is_complete_not_a_floor,
               test_sweeps_are_idempotent,
               test_a_pattern_selects_without_losing_coverage,
               test_pending_pages_are_polled_not_reported_empty,
               test_an_all_pending_job_is_never_an_empty_log,
               test_a_mid_sweep_renewal_never_claims_complete,
               test_too_large_responses_downsize_and_finish_complete,
               test_persistent_too_large_degrades_to_partial_or_raises,
               test_rows_without_recordnumbers_stall_but_keep_data,
               test_auto_limit_resizes_from_measured_rows):
        print(f"{fn.__name__}:")
        try:
            fn()
        except BaseException as e:                       # noqa: BLE001
            check(f"{fn.__name__} (crashed)", False, f"{type(e).__name__}: {e}")
        print()

    if FAILED:
        print(f"FAILED: {len(FAILED)} check(s): {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
