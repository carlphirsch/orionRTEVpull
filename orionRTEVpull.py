#!/usr/bin/env python3
"""Headless Orion *web tier* login + Real-Time Event Log Viewer query.

The RTEV DataProvider lives on the web tier (443, forms auth) -- NOT the SWIS
REST API (17774, basic auth). This logs in with a local Orion account and
drives DataProvider.aspx directly. No browser required. Endpoint behavior
(async job model, over-fetch, the response-size ceiling, window mechanics) is
described in the README; comments here state only what the code depends on.

Public surface:

    connect(host, user, password)  -> (session, response, authed)
    fetch_events(session, host, node_id, ...)  -> one page: the raw JSONP
                                                  payload dict; never a
                                                  pending-empty result
    search(session, host, node_id, regex, ...) -> SearchResult: unpacks as
                                                  (hits, unique_events_seen)
                                                  and carries completeness
                                                  flags; deep=/auto_limit=
    search_many(host, user, password, node_ids, regex, ...)
                                               -> per-node results, bounded
                                                  worker threads
    sort_hits / format_hit / ms_to_utc / as_text  -> rendering helpers
    load_env / load_targets / resolve          -> CLI plumbing, shared with
                                                  the examples

Also public: OrionError / SessionExpired / RtevTimeout / ResponseTooLarge,
the OrionSession and SearchResult types (SearchResult.as_dict() gives the
serializable per-node shape search_many() returns), and the tunables MAX_LIMIT,
SAFE_RESPONSE_MB, AUTO_LIMIT_CAP, PROBE_LIMIT, DEEP_MAX_ROUNDS,
LOGIN_TIMEOUT, FILE_READ_MAX, RETRIES, RETRY_STATUS, JOB_*.
`login` is the bare flow; prefer connect(). Underscore names are internal
and may change freely.

Errors: everything raised here derives from OrionError (a RuntimeError);
RtevTimeout also derives from TimeoutError. Network-layer exceptions are
wrapped, never allowed to escape raw.

Reading order: constants, exceptions, the result type, config helpers, session and auth,
response parsers, the HTTP round trip, the async fetch, the paging search,
multi-node, output formatting, CLI.
"""
import argparse
import concurrent.futures
import dataclasses
import datetime
import getpass
import json
import math
import numbers
import os
import re
import sys
import threading
import time
import zlib
from html.parser import HTMLParser

import requests
import urllib3

# Ceiling on cLimit for manually chosen limits. The server's real constraint is
# serialized response bytes, not rows (~4.2-4.4 MB tips it to HTTP 500 -- see
# see the response-size gotcha); 1700 keeps a full over-fetch under that line for
# typical ~0.6 KB rows. Fat-message logs can still fail below this.
MAX_LIMIT = 1700

# Serialized-response byte budget that auto_limit sizes pages against, with
# margin under the ceiling documented at MAX_LIMIT.
SAFE_RESPONSE_MB = 4.0

# Hard cap on an auto-sized page limit. Deliberately above MAX_LIMIT: the
# manual ceiling assumes worst-case row fatness, while auto-limit sizes from
# the MEASURED bytes-per-row, so it can safely run larger pages on lean logs.
# The byte budget above is what actually governs; this only bounds the lever.
AUTO_LIMIT_CAP = 2400

# Limit for the tiny probe that distinguishes a too-large 500 from a
# missing-right 500 (byte-identical on the wire); also the floor that
# downsizing and auto-limit sizing never go below.
PROBE_LIMIT = 50

# deep=True re-sweeps until no new uniques arrive; hard stop after this many
# rounds regardless.
DEEP_MAX_ROUNDS = 6

# Wall-clock ceiling on a login exchange: generous (a real login is ~1s) but
# finite, so a wedged console cannot hang the tool.
LOGIN_TIMEOUT = 60

# Transient conditions worth retrying rather than aborting a long sweep.
RETRY_STATUS = (429, 502, 503, 504)
RETRIES = 3

# Byte ceiling on any operator-supplied file this module reads whole (--env,
# --targets). Generous for their purpose (a credential file is a few hundred
# bytes) and finite, so a path pointed at a character device cannot grow the
# read buffer without limit.
FILE_READ_MAX = 1 << 20

# KNOWN HAZARD, deliberately NOT mitigated by truncating the searched text.
# The --pattern regex is operator-supplied and runs with no wall-clock guard
# (CPython's sre holds the GIL for the whole match and only polls signals on
# the main thread, so a match inside a search_many worker freezes the entire
# process -- Ctrl-C included -- until it finishes). A catastrophic-backtracking
# pattern against a long Message can therefore run for effectively forever.
#
# Capping the text handed to re (msg[:N], and equally re.search(msg, 0, N))
# was tried and REVERTED before release: measurement showed it makes things worse.
#   * It does not bound the cost. Backtracking is exponential in the length of
#     the run it chews, so a cap only lowers the base: ~2^(N/2) at any N worth
#     having. It helps polynomial patterns only.
#   * It CONVERTS FAST SUCCESSES INTO HANGS. Truncation deletes the text that
#     terminated the match, and a nested quantifier that fails is exponential
#     where the same pattern succeeding was instant: `(a+)+ shutdown` against
#     "a"*5000 + " shutdown" returns a hit immediately on the full field and
#     never returns on a 4096-char prefix. That strictly enlarges the hang set.
#   * It corrupts results. A prefix invents an end-of-string and a token
#     boundary, so $, \Z, \b and lookarounds are evaluated against text the
#     operator never saw -- fabricating hits whose stored preview does not even
#     contain the match, and dropping real ones whose zero-width assertion
#     straddles the cut. In a forensics tool that is worse than being slow.
# Bounding the pattern's cost (a linear-time engine, or running the match in a
# killable subprocess) is the only correct fix; both are out of scope for a
# one-dependency single-file tool. The operator owns the pattern.


class OrionError(RuntimeError):
    """Base for every error raised by this module."""


class SessionExpired(OrionError):
    """The forms-auth cookie is gone or expired; the endpoint served the login
    page instead of data. Recoverable by re-authenticating."""


class RtevTimeout(OrionError, TimeoutError):
    """A wall-clock deadline expired: the agent job never went terminal, or
    a request or read could not finish within its budget."""


class ResponseTooLarge(OrionError):
    """The server refused to serialize the response (the byte ceiling -- see
    MAX_LIMIT). Recoverable by retrying a smaller limit; search() does that
    automatically, restarting the sweep so the anchor keeps its depth."""


class SearchResult:
    """What search() returns. Unpacks like the historical two-tuple --
    `hits, scanned = search(...)` still works -- and additionally carries
    the completeness verdicts that are also printed to stderr:

        exhausted  the whole log was reached
        partial    a mid-sweep failure ended the run early
        stalled    rows without usable RecordNumbers pinned the paging anchor
        renewed    the session expired mid-sweep and was renewed, restarting
                   the server's paging window; depth coverage is unreliable
                   and any later end-of-data page cannot be trusted

    `complete` is True only when exhausted with no other flag set; anything
    else is a floor, not an answer. In deep mode `exhausted` is a whole-log
    verdict: it needs BOTH the final round reaching end-of-data AND the deep
    loop converging (a round that found nothing new), so a spent round budget
    or a failed re-login reports incomplete. Not a real tuple: `== (hits,
    scanned)` is False, and the object is always truthy.
    """
    __slots__ = ("hits", "scanned", "exhausted", "partial", "stalled",
                 "renewed")

    def __init__(self, hits, scanned, exhausted=False, partial=False,
                 stalled=False, renewed=False):
        self.hits, self.scanned = hits, scanned
        self.exhausted, self.partial, self.stalled = exhausted, partial, stalled
        self.renewed = renewed

    @property
    def complete(self):
        return (self.exhausted and not self.partial and not self.stalled
                and not self.renewed)

    def as_dict(self):
        """A plain dict of the result and all its verdicts -- the serialization
        the object itself cannot offer through json.dumps (its tuple-unpacking
        shim makes it neither a real tuple nor a mapping). This is exactly the
        per-node shape search_many() returns, so callers can treat single- and
        multi-node results uniformly. Note hits still carry datetime `utc`
        values, so json.dumps(res.as_dict(), default=str) is the serializable
        form -- same caveat the raw hit dicts always had."""
        return {"hits": self.hits, "scanned": self.scanned,
                "exhausted": self.exhausted, "partial": self.partial,
                "stalled": self.stalled, "renewed": self.renewed,
                "complete": self.complete}

    def __iter__(self):                     # two-tuple unpacking compatibility
        return iter((self.hits, self.scanned))

    def __getitem__(self, i):
        return (self.hits, self.scanned)[i]

    def __len__(self):
        return 2

    def __repr__(self):
        return (f"SearchResult(hits={len(self.hits)}, scanned={self.scanned},"
                f" exhausted={self.exhausted}, partial={self.partial},"
                f" stalled={self.stalled}, renewed={self.renewed})")


def _read_capped(path, what, cap=FILE_READ_MAX):
    """Read an operator-supplied text file whole, under a byte cap.

    Shared by load_env and load_targets deliberately. Bounding these one at a
    time is exactly how this defect kept coming back: --env was capped while
    --targets, the sibling operator path, still read unbounded. Aimed at a
    character device (/dev/zero) an unbounded read grows the buffer at
    gigabytes per second until the machine gives out, so every whole-file read
    in this module goes through here.

    Raises OrionError past the cap; OSError and the decode ValueError are left
    to the caller, which names the file kind in its own message.
    """
    with open(path) as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise OrionError(f"{what} {path!r} is larger than {cap} bytes; this "
                         "expects a small file, not a stream or a device")
    return data


def load_env(path):
    """Parse a KEY=VALUE dotenv file: optional `export`, at most one matching
    quote pair stripped, inline ` # comment` honored only on unquoted values
    (so '#' or a trailing quote inside a password survives). Raises OrionError
    so the CLI reports a bad file in one clean line."""
    d = {}
    try:
        # Bounded whole-file read rather than iterating an open stream: on a
        # character device the line loop never sees a newline or an EOF.
        data = _read_capped(path, "env file")
        # split("\n"), NOT splitlines(). The file is opened in text mode, so
        # universal newlines have already folded \r\n and \r into \n -- which
        # makes this byte-for-byte what iterating the file object produced.
        # splitlines() ALSO breaks on VT, FF, FS, GS, RS, NEL, U+2028 and
        # U+2029, so a password containing any of them (they arrive from
        # pasting out of Word or a PDF) was silently truncated at that
        # character and the tool then authenticated with the wrong secret.
        for raw in data.split("\n"):
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            else:
                v = v.split(" #", 1)[0].rstrip()
            d[k.strip()] = v
    except OSError as e:
        raise OrionError(f"cannot read env file {path!r}: {e.strerror}") from e
    except ValueError as e:
        # UnicodeDecodeError from a non-UTF-8 byte: a bad file, not a crash.
        raise OrionError(f"cannot decode env file {path!r} as text: {e}") from e
    return d


def resolve(cli, envfile, *keys):
    """Resolve one setting: CLI flag, then environment variable, then env
    file. Shared with the examples. Deliberately no SWIS_* fallback -- SWIS
    is a separate service on its own port, with its own authentication."""
    if cli:
        return cli
    for k in keys:
        if os.environ.get(k):
            return os.environ[k]
    for k in keys:
        if envfile.get(k):
            return envfile[k]
    return None


def load_targets(path):
    """Read a JSON list of target nodes (the examples' --targets file).
    Shape: [{"node_id": 1234, "caption": "HOST01", ...}, ...]. Validates here
    so every failure is one clean line naming the offending entry."""
    try:
        # Same bounded read as load_env: --targets is the sibling
        # operator-supplied path, and json.load(f) issues an unbounded read.
        targets = json.loads(_read_capped(path, "targets file"))
    except OSError as e:
        raise OrionError(f"cannot read targets file {path!r}: {e.strerror}") from e
    except RecursionError as e:
        # Deeply nested JSON. Not a ValueError, so it would otherwise escape.
        raise OrionError(f"targets file {path!r} is nested too deeply: {e}") from e
    except ValueError as e:
        raise OrionError(f"targets file {path!r} is not valid JSON: {e}") from e

    if not isinstance(targets, list):
        raise OrionError(f"targets file {path!r} must contain a JSON list, "
                         f"got {type(targets).__name__}")
    for i, t in enumerate(targets):
        if not isinstance(t, dict) or "node_id" not in t:
            raise OrionError(f"targets file {path!r} entry {i} needs a "
                             f"'node_id' key: {str(t)[:80]}")
        # A null or non-integer node_id is dropped from the query string by
        # requests, and the endpoint answers a missing cNodeId with a 500 that
        # reads like a permissions problem -- so catch it here instead.
        if (not isinstance(t["node_id"], int) or isinstance(t["node_id"], bool)
                or t["node_id"] <= 0):
            raise OrionError(f"targets file {path!r} entry {i} needs a positive "
                             f"integer 'node_id': {t['node_id']!r}")
    return targets


class OrionSession(requests.Session):
    """A requests.Session that can log itself back in. Carrying credentials
    lets fetch_events() recover from a cookie expiry mid-sweep, and lets
    search() dispatch a fresh server-side job, which extends the tracked
    window -- the mechanism deep mode rides. The password
    stays in memory only; never logged, never in a URL."""

    def __init__(self, host, user, password, verify=True):
        super().__init__()
        self.orion_host = host
        self.orion_user = user
        self._password = password
        self.verify = verify
        # gzip only. requests would otherwise advertise "gzip, deflate", and
        # a deflate body can only be decoded by urllib3, whose decoder loop
        # is outside this module's wall clock (see _read_bounded).
        self.headers["Accept-Encoding"] = "gzip"
        # Bumped by reauth(). search() watches this: a re-login starts a fresh
        # server-side job, which resets the paging window.
        self.reauth_count = 0

    def reauth(self, deadline=None):
        """Re-run the forms login on this same session. Returns True on success.

        Clears the cookie jar first: success is inferred from an .ASPXAUTH
        cookie, and the expired ticket that triggered the re-auth still
        lingers in the jar -- without the clear, a failed re-login would
        always look successful.

        A None deadline is given the LOGIN_TIMEOUT default (as login() does),
        so a direct s.reauth() cannot read a dribbling login page unbounded;
        internal callers pass their own tighter deadline.
        """
        if deadline is None:
            deadline = time.monotonic() + LOGIN_TIMEOUT
        self.cookies.clear()
        self.reauth_count += 1
        try:
            _, _, authed = _do_login(self, self.orion_host, self.orion_user,
                                     self._password, deadline=deadline)
        except requests.exceptions.SSLError as e:
            # reauth() does not go through connect(), so it must handle the
            # cert error itself: if the server's certificate stopped verifying
            # mid-sweep, wrap it (SSLError derives from OSError, not
            # RuntimeError, and would otherwise escape every handler).
            raise OrionError(
                f"re-authentication to {self.orion_host} failed: the server "
                f"certificate no longer verifies: {' '.join(str(e).split())[:120]}"
            ) from e
        return authed


def _has_auth_cookie(session, host):
    """True only if a usable .ASPXAUTH cookie for THIS host is in the jar.

    Checks the cookie's domain (an SSO redirect can set its own .ASPXAUTH on
    another host, which must not count), rejects empty values, and matches
    the name exactly rather than by prefix.
    """
    hostname = host.split(":")[0].strip().lower().rstrip(".")
    # http.cookiejar stores a single-label host's cookies under "<host>.local"
    # (eff_request_host), so bare internal hostnames need the alias.
    aliases = {hostname}
    if "." not in hostname:
        aliases.add(hostname + ".local")
    for c in session.cookies:
        if (c.name or "").lower() != ".aspxauth" or not c.value:
            continue
        domain = (c.domain or "").lstrip(".").lower().rstrip(".")
        if not domain:
            return True
        if any(a == domain or a.endswith("." + domain) for a in aliases):
            return True
    return False


class _HiddenFieldParser(HTMLParser):
    """Collect <input> name/value pairs from an ASP.NET login page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        attributes = {}
        for key, value in attrs:            # first occurrence wins, per HTML
            attributes.setdefault(key, value)
        name = attributes.get("name")
        if name and name not in self.fields:     # first render wins
            self.fields[name] = attributes.get("value") or ""


def _tag_end(page, start):
    """Index of the '>' that closes the tag at `start`, or -1. Quote-aware:
    an attribute value may legitimately contain '>'. An unterminated tag ends
    the scan (and the caller's), keeping the pass linear."""
    quote = None
    for j in range(start, len(page)):
        ch = page[j]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return j
    return -1


def _ifind(page, needle, pos):
    """ASCII-case-insensitive find returning an index into `page` itself.

    Not lower(): it can change string length (U+0130), shifting every index.
    re.ASCII matters as much as re.I -- every needle here is an HTML token,
    and Unicode folding would let a non-tag close one: U+017F folds to "s",
    so "</ſcript>" would match "</script" and end a raw-text strip
    early, exposing a decoy field inside it.
    """
    m = re.compile(re.escape(needle), re.I | re.A).search(page, pos)
    return m.start() if m else -1


def _strip_spans(page, opener, closer):
    """Remove opener..closer spans with a single linear pass."""
    out, pos = [], 0
    while True:
        i = _ifind(page, opener, pos)
        if i < 0:
            out.append(page[pos:])
            return "".join(out)
        out.append(page[pos:i])
        j = _ifind(page, closer, i + len(opener))
        if j < 0:
            return "".join(out)                  # unterminated: drop the rest
        pos = j + len(closer)


def _scrape_hidden_fields(page):
    """Hidden form fields from a login page, in three linear passes: strip
    raw-text elements and comments (a decoy <input> inside one must not beat
    the real field), extract only well-formed <input ...> tags (unterminated
    runs are skipped, never rescanned -- what keeps pathological markup
    linear), then HTML-parse just those tags for correct attribute handling.
    """
    # Raw-text elements before comments: "<!--" inside <script> is not a
    # comment opener, and stripping comments first can swallow the page.
    for tag in ("script", "style", "textarea", "title", "noscript"):
        page = _strip_spans(page, "<" + tag, "</" + tag + ">")
    page = _strip_spans(page, "<!--", "-->")

    tags, pos = [], 0
    while True:
        i = _ifind(page, "<input", pos)
        if i < 0:
            break
        j = _tag_end(page, i)
        if j < 0:
            break                                # unterminated; nothing usable
        tags.append(page[i:j + 1])
        pos = j + 1

    parser = _HiddenFieldParser()
    try:
        parser.feed("".join(tags))
        parser.close()
    except Exception:                            # malformed markup
        pass                                     # keep whatever was collected
    return parser.fields


def _host_of(url):
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def _send_bounded(s, method, url, timeout, deadline=None, **kw):
    """Send one request via the adapter, bypassing Session.send(), which
    reads a redirect's entire body outside any wall clock. Cookies and proxy
    settings are applied by hand to match what Session.send would do. The
    request runs in a worker thread under a wall-clock watchdog, because the
    adapter reads status+headers under a per-socket-op timeout that a
    dribbling server never trips.
    """
    def dispatch(socket_timeout):
        prepped = s.prepare_request(requests.Request(method=method, url=url, **kw))
        settings = s.merge_environment_settings(prepped.url, {}, True, s.verify,
                                                None)
        r = s.get_adapter(prepped.url).send(prepped, timeout=socket_timeout,
                                            **settings)
        return r, prepped

    if deadline is None:
        deadline = time.monotonic() + timeout

    left = deadline - time.monotonic()
    if left <= 0:
        raise RtevTimeout(f"ran out of time before contacting {_host_of(url)}")
    box = {}
    # Clamp the socket timeout to the budget so an abandoned worker exits
    # promptly instead of pinning a thread and a socket.
    worker_timeout = max(0.5, min(timeout, left))

    def run():
        try:
            r, prepped = dispatch(worker_timeout)
        except BaseException as e:              # noqa: BLE001 - re-raised below
            box["e"] = e
            return
        if box.get("abandoned"):
            # Close without touching the cookie jar: a stale ticket must not
            # overwrite one a later login just obtained.
            try:
                r.close()
            except Exception:
                pass
        else:
            requests.cookies.extract_cookies_to_jar(s.cookies, prepped, r.raw)
            box["r"] = r

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    # Clamp the join: Thread.join() converts its argument to an absolute
    # deadline and raises a bare OverflowError on inf (or anything past
    # time_t) and a bare ValueError on NaN, either of which would escape the
    # OrionError contract. The isfinite test covers NaN, which min() would
    # otherwise pass straight through -- the CLI rejects a non-finite
    # --poll-timeout, but a library caller can still supply one. A day is
    # longer than any real budget, so the clamp is unreachable in practice.
    worker.join(min(left, 86400.0) if math.isfinite(left) else 86400.0)
    if worker.is_alive():
        # Abandon: the worker exits on its clamped socket timeout and closes
        # its own response; the caller returning on time is what matters.
        box["abandoned"] = True
        raise RtevTimeout(
            f"timed out waiting for response headers from {_host_of(url)} "
            "(the server was sending, but too slowly to finish in budget)")
    if "e" in box:
        raise box["e"]
    return box["r"]


def _login_request(s, method, url, deadline, follow=0, **kw):
    """A GET/POST for the login flow under the same wall-clock deadline and
    error wrapping as the data path. Returns (response, body_text); the body
    is already consumed -- use the response only for status_code. Redirects
    are followed manually, at most `follow` hops, so every hop stays inside
    the budget. The login POST uses follow=0: the .ASPXAUTH cookie arrives on
    the 302 itself, and chasing it would download the dashboard on every
    login and mid-sweep re-auth.
    """
    origin = _host_of(url)          # url is rebound while following hops
    for hop in range(follow + 1):
        timeout = 30
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RtevTimeout(
                    f"ran out of time during the login exchange with {origin}")
            timeout = min(timeout, max(1.0, left))
        try:
            r = _send_bounded(s, method, url, timeout, deadline=deadline, **kw)
            body = _read_bounded(r, deadline)
        except (RtevTimeout, OrionError):
            raise
        except requests.exceptions.SSLError:
            raise                    # connect() handles this one specifically
        except requests.exceptions.RequestException as e:
            raise OrionError(f"cannot reach the Orion login page at "
                             f"{origin}: {type(e).__name__}: "
                             f"{' '.join(str(e).split())[:140]}") from e
        except OSError as e:
            # A BARE OSError, which RequestException subclasses but does not
            # cover: requests raises this from cert_verify when verify= or
            # REQUESTS_CA_BUNDLE names a path that does not exist, before any
            # socket is opened. Not a RuntimeError, so unwrapped it would
            # escape the module's catch-all.
            raise OrionError(f"cannot start the request to {origin}: "
                             f"{' '.join(str(e).split())[:140]}") from e
        except ValueError as e:
            # IDNA UnicodeError -- outside the RuntimeError hierarchy.
            raise OrionError(f"cannot use the host {origin!r}: "
                             f"{' '.join(str(e).split())[:140]}") from e

        location = r.headers.get("Location")
        if hop < follow and r.status_code in (301, 302, 303, 307, 308) and location:
            try:
                url = requests.compat.urljoin(url, location)
            except ValueError as e:
                # A malformed Location (a bracketed non-IP host, say) makes
                # urljoin raise bare -- again outside the hierarchy.
                raise OrionError(
                    f"the login page at {origin} redirected to a location "
                    f"that cannot be parsed ({location[:80]!r}): "
                    f"{' '.join(str(e).split())[:100]}") from e
            if r.status_code in (301, 302, 303):
                method = "GET"       # per RFC, and the body must not be resent
                kw.pop("data", None)
            continue
        break

    if r.status_code in (301, 302, 303, 307, 308) and follow:
        if not r.headers.get("Location"):
            raise OrionError(f"the login page at {origin} returned HTTP "
                             f"{r.status_code} with no Location header, so the "
                             "redirect cannot be followed")
        raise OrionError(f"the login page at {origin} redirected more than "
                         f"{follow} times. A console that redirects like this "
                         "is usually fronted by an SSO provider, which this "
                         "tool cannot authenticate against -- it needs a LOCAL "
                         "Orion account.")
    if r.status_code >= 400:
        raise OrionError(f"the Orion login page at {origin} returned HTTP "
                         f"{r.status_code} -- the host answered, so this is not "
                         "a connectivity problem")
    return r, body


def _do_login(s, host, user, password, deadline=None):
    """Drive the ASP.NET forms login on an existing session object.

    Network failures are wrapped in OrionError (see _login_request). Bounded by
    `deadline` when a caller has one -- reauth() passes the sweep's, so a
    dribbling login page cannot outlast the poll budget.
    """
    url = f"https://{host}/Orion/Login.aspx"
    _, page = _login_request(s, "GET", url, deadline, follow=5)

    fields = _scrape_hidden_fields(page)

    def field(name):
        return fields.get(name, "")

    payload = {
        "__EVENTTARGET": "", "__EVENTARGUMENT": "",
        "__VIEWSTATE": field("__VIEWSTATE"),
        "__VIEWSTATEGENERATOR": field("__VIEWSTATEGENERATOR"),
        "__AntiXsrfTokenInput": field("__AntiXsrfTokenInput"),
        "ctl00$BodyContent$Username": user,
        "ctl00$BodyContent$Password": password,
        "ctl00$BodyContent$PasswordPolicySettingsInput": field(
            "ctl00$BodyContent$PasswordPolicySettingsInput"),
        "ctl00$BodyContent$LoginButton": "Login",
    }
    ev = field("__EVENTVALIDATION")
    if ev:
        payload["__EVENTVALIDATION"] = ev

    # Without __VIEWSTATE the POST cannot succeed; say so plainly rather than
    # letting it surface as a bad password.
    if not payload["__VIEWSTATE"]:
        raise OrionError(
            f"could not find __VIEWSTATE on the login page at {host}. That page "
            "is probably not an Orion forms login -- check the hostname, and "
            "whether the console now redirects to an SSO provider.")

    # follow=0: the auth cookie is set on the 302, so there is nothing to
    # gain by chasing it -- see _login_request.
    r2, _ = _login_request(s, "POST", url, deadline, data=payload)
    # The auth cookie is the only reliable success signal: a failed login also
    # returns HTTP 200 (the login page again, with an error label).
    authed = _has_auth_cookie(s, host)
    return s, r2, authed


def login(host, user, password, verify=True, deadline=None):
    """Bare forms login; returns (session, response, authed). Prefer
    connect(), which validates the host and handles certificate failures.
    Network errors are wrapped into OrionError either way."""
    s = OrionSession(host, user, password, verify=verify)
    if deadline is None:
        deadline = time.monotonic() + LOGIN_TIMEOUT
    try:
        return _do_login(s, host, user, password, deadline=deadline)
    except Exception:
        s.close()                       # do not leak the connection pool
        raise


# RFC 1035 label shape plus underscore (real Windows/AD hosts have them),
# ASCII only, digits-only port: anything looser
# can push requests' IDNA encoding into UnicodeError outside our hierarchy.
_HOST_RE = re.compile(r"[A-Za-z0-9_-]{1,63}(\.[A-Za-z0-9_-]{1,63})*\.?"
                      r"(:[0-9]{1,5})?\Z")


def _check_host(host):
    """Reject anything but a bare hostname[:port]: host is interpolated into
    the URL the password is POSTed to, and can arrive from a dotenv file or
    an inherited environment variable."""
    if not host or not _HOST_RE.match(host):
        raise OrionError(f"invalid Orion host {host!r}: expected a bare "
                         "hostname or host:port, with no scheme, path, or "
                         "credentials")
    if ":" in host:
        port = int(host.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise OrionError(f"invalid Orion host {host!r}: port {port} is "
                             "outside 1-65535")
    return host


def connect(host, user, password, insecure=False):
    """Login, verifying the server certificate; returns (session, resp,
    authed). Fails CLOSED on a certificate error -- the login POSTs the
    password, so an unverified peer must not receive it. insecure=True
    (CLI: --insecure) is the deliberate per-run override."""
    _check_host(host)
    try:
        return login(host, user, password)
    except requests.exceptions.SSLError as e:
        reason = " ".join(str(e).split())[:200]
        if not insecure:
            raise OrionError(
                f"TLS certificate verification failed for {host}: {reason}\n"
                "  Refusing to send credentials over an unverified connection. "
                "Add the Orion certificate/CA to your trust store, or pass "
                "--insecure to override for this run.") from e
        print(f"WARNING: proceeding with TLS verification DISABLED for {host}. "
              "Traffic stays encrypted but the server identity is NOT "
              f"authenticated.\n  cause: {reason}", file=sys.stderr)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            return login(host, user, password, verify=False)
        except requests.exceptions.SSLError as e2:
            # Failing with verification OFF means the handshake itself is
            # broken -- not something --insecure can paper over.
            raise OrionError(
                f"the TLS handshake with {host} failed even with verification "
                f"disabled: {' '.join(str(e2).split())[:160]}") from e2
    # Non-TLS failures are already wrapped into OrionError by _login_request.


def as_text(v):
    """Coerce a wire field to a string (None -> ""). Public because no field
    in the response is contractually a string."""
    if v is None:
        return ""
    return v if isinstance(v, str) else str(v)


def _wire_int(v):
    """A wire value as an int, or None. Tolerates numeric strings (a future
    serialization change must not silently change behavior), excludes bool,
    and absurd digit strings yield None instead of tripping CPython's
    int/str conversion limit."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdecimal():
        try:
            return int(v.strip())
        except ValueError:
            return None
    return None


def _rec_int(event):
    """RecordNumber as an int for the paging anchor and dedupe, or None.
    Non-dict rows yield None rather than an AttributeError."""
    if not isinstance(event, dict):
        return None
    return _wire_int(event.get("RecordNumber"))


def ms_to_utc(v):
    """MS-AJAX /Date(1786455966299)/ -> datetime (UTC), or None if unparseable."""
    m = re.search(r"/Date\((-?\d+)", str(v))
    if not m:
        return None
    try:
        return datetime.datetime.fromtimestamp(int(m.group(1)) / 1000,
                                               datetime.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


# JobPollingStatus (RealTimePollingStatus enum): 0 Unknown, 1 Initialized,
# 2 Running, 3 Error (terminal), 4 Finished (terminal). Poll while 0/1/2.
JOB_UNKNOWN, JOB_INIT, JOB_RUNNING, JOB_ERROR, JOB_DONE = range(5)

# Server-side errors reach the client verbatim and mean nothing to a reader.
# Matched as substrings and appended to the server's own text as an explanation.
_CRYPTIC = (
    ("sequence contains no matching element",
     'log not found on this node. Either the log name is wrong, or the node '
     'returned no log list at all (an unreachable or down agent looks '
     'identical here).'),
    ("0x40004",
     "the agent's WMI query timed out reading this log. Common on the Security "
     "log, which is large and slow enough that the read regularly exceeds the "
     "server-side limit under the inherited node credential."),
    ("0x800706be",
     "the RPC call to the node's WMI provider failed, so the event-log "
     "provider on that host is broken or unreachable -- worth investigating "
     "on the node itself."),
)


def _explain(msg):
    """Return a plain-language explanation for a known server error, or None."""
    low = msg.lower()
    for needle, explanation in _CRYPTIC:
        if needle in low:
            return explanation
    return None


def _looks_like_login_page(text):
    """True if the body is the Orion login form rather than endpoint data."""
    return ("ctl00$BodyContent$Password" in text
            or "BodyContent_Password" in text
            or "/Orion/Login.aspx" in text)


def _html_summary(text, status):
    """Reduce an Orion HTML error page to one useful line.

    The endpoint answers a rights failure or a bad NodeID with a full HTML
    error page, so the raw body is thousands of characters of markup. Prefer
    the Error.aspx Message= parameter, then <title>, then stripped text.
    """
    # Cap first: the tag-stripping patterns below are quadratic on pathological
    # markup, and this only ever produces a one-line error summary.
    text = text[:100_000]
    m = re.search(r"[?&]Message=([^\"'&]+)", text)
    if m:
        return requests.utils.unquote(m.group(1)).replace("+", " ")[:200]
    m = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    if m and m.group(1).strip():
        return " ".join(m.group(1).split())[:200]
    stripped = " ".join(re.sub(r"<[^>]+>", " ", text).split())
    return stripped[:200] if stripped else f"HTTP {status}, empty body"


def _response_socket(r):
    """Best-effort handle to the live socket under a STREAMED response, so the
    body read can re-clamp its recv timeout to the remaining wall-clock budget
    (see _read_bounded). Returns None when the socket cannot be reached -- the
    urllib3 1.26 fallback path, or a build that hides it -- and the caller then
    falls back to the between-recv deadline check alone, exactly as before this
    shim existed.

    Total by construction: it reaches into another library's private internals,
    so EVERY failure returns None. getattr/hasattr swallow only AttributeError,
    while a property or __getattr__ on the way down may raise anything at all --
    and this runs outside _read_bounded's try, so an escape would leave a raise-
    only function as a bare builtin."""
    try:
        raw = getattr(r, "raw", None)
        sock = getattr(getattr(raw, "_connection", None), "sock", None)
        if sock is None:
            # Some builds expose only the buffered file-object chain
            # (socket -> SocketIO -> BufferedReader).
            fp2 = getattr(getattr(raw, "_fp", None), "fp", None)
            sock = getattr(getattr(fp2, "raw", None), "_sock", None)
        return sock if hasattr(sock, "settimeout") else None
    except Exception:
        return None


def _read_bounded(r, deadline, cap=64 * 1024 * 1024):
    """Read a streamed response body under a hard wall-clock deadline.

    Reads r.raw via read1() so the deadline is consulted on every recv --
    requests' `timeout` bounds socket operations, not the response, and
    iter_content(n) blocks until n bytes arrive, so a dribbling server trips
    neither. gzip is inflated HERE with zlib: urllib3's read1(decode_content=
    True) loops internally until the decoder yields output, bypassing the
    deadline entirely. The size cap therefore counts DECOMPRESSED bytes.
    Raw-read errors are re-raised as their requests equivalents so they stay
    inside the module's exception contract (retryable, catchable).

    The deadline is HARD, not merely checked between recvs: before every read
    the socket's own timeout is re-clamped to the time left (_response_socket),
    so a body that stalls after its headers cannot overshoot by a whole socket
    timeout -- the header phase's watchdog and this clamp bound the two phases
    symmetrically. A recv that trips that clamped timeout past the deadline is
    surfaced as RtevTimeout, not a transport error. When the socket handle is
    unreachable (the 1.26 fallback) the between-recv check remains the bound,
    as before -- an overshoot of at most one recv, never a hang.
    """
    fp = r.raw
    encoding = (r.headers.get("Content-Encoding") or "").strip().lower()
    chunked = "chunked" in (r.headers.get("Transfer-Encoding") or "").lower()

    # An encoding this module cannot inflate itself is REFUSED, never handed
    # to urllib3's decoder loop, which runs outside this deadline (see the
    # docstring). OrionSession pins Accept-Encoding to gzip so a compliant
    # server never sends one; this is the guard for a server that ignores it.
    if encoding and encoding not in ("gzip", "x-gzip", "identity"):
        r.close()
        raise OrionError(
            f"the server sent Content-Encoding {encoding!r}, which this "
            "tool cannot decode safely; only gzip is accepted (and is "
            "all the request advertised)")

    # One mode decision up front. gzip (and its RFC alias x-gzip): inflate
    # HERE with zlib. raw: no decoding needed. legacy (urllib3 1.26, no
    # read1()): iter_content(1)
    # keeps the deadline honest but decodes for us, so the truncation check
    # cannot run (the README notes this degradation; upgrading urllib3
    # restores it).
    if not hasattr(fp, "read1"):
        mode = "legacy"
    elif encoding in ("gzip", "x-gzip"):
        mode = "gzip"
    else:
        mode = "raw"
    inflater = (zlib.decompressobj(16 + zlib.MAX_WBITS) if mode == "gzip"
                else None)
    fallback = r.iter_content(1) if mode == "legacy" else None

    # Tracks the CURRENT member's trailer -- a complete first member must not
    # mask a truncated second one.
    member_done = False

    def read_some():
        if fallback is not None:
            return next(fallback, b"")
        try:
            # decode_content=False always -- see the docstring.
            raw = fp.read1(65536, decode_content=False)
        except TypeError as e:
            raise OrionError("this urllib3 build's read1() does not support "
                             "decode_content; please upgrade urllib3") from e
        except urllib3.exceptions.DecodeError as e:
            raise requests.exceptions.ContentDecodingError(e) from e
        except urllib3.exceptions.ReadTimeoutError as e:
            raise requests.exceptions.ConnectionError(e) from e
        except urllib3.exceptions.SSLError as e:
            raise requests.exceptions.SSLError(e) from e
        except urllib3.exceptions.ProtocolError as e:
            # Reset or truncated body. Name it as requests would --
            # ChunkedEncodingError only if actually chunked.
            if chunked:
                raise requests.exceptions.ChunkedEncodingError(e) from e
            raise requests.exceptions.ConnectionError(e) from e
        except urllib3.exceptions.HTTPError as e:
            raise requests.exceptions.ConnectionError(e) from e
        return raw

    def inflate(raw):
        """Decompress one packet. An empty result mid-stream is normal (the
        decoder buffers). Handles multi-member gzip -- a decompressobj stops
        at the first trailer -- and ignores post-trailer padding that does
        not start a new member, as other gzip readers do."""
        nonlocal inflater, member_done
        if inflater is None:
            return raw
        pieces, data = [], raw
        while True:
            try:
                pieces.append(inflater.decompress(data))
            except zlib.error as e:
                raise requests.exceptions.ContentDecodingError(
                    f"could not decompress the gzip response: {e}") from e
            if not inflater.eof:
                member_done = False         # still mid-member
                break
            member_done = True
            leftover = inflater.unused_data
            if not leftover.startswith(b"\x1f\x8b"):
                # A non-empty PREFIX of the magic (a lone 0x1f) is a member
                # header cut in half, not padding: refuse it exactly as a
                # full magic would be, or the next member is dropped in
                # silence. Padding that cannot start a header still passes.
                if leftover and b"\x1f\x8b".startswith(leftover):
                    member_done = False
                break                       # trailing padding, not a member
            # Bytes that begin with the magic are treated as a member and
            # must decode as one -- the truncation check errs strict.
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data, member_done = leftover, False
        return b"".join(pieces)

    # The socket whose recv timeout we re-clamp each pass, and its send-time
    # timeout (_send_bounded set it), which is the CEILING the clamp may never
    # exceed. The clamp may only ever SHORTEN a recv: lengthening would both
    # stretch the wait to the whole remaining budget and convert a transport
    # read-timeout -- which _fetch_once retries -- into an RtevTimeout it
    # deliberately does not retry. So an unreadable or unusable ceiling means
    # DO NOT CLAMP, leaving the between-recv check as the bound (an overshoot
    # of at most one socket timeout, exactly as before this clamp existed).
    # Skipped entirely on the legacy path: iter_content(1) already consults the
    # deadline every byte, so clamping there buys nothing and would cost one
    # settimeout syscall per byte.
    sock = None if mode == "legacy" else _response_socket(r)
    base_to = None
    if sock is not None:
        # The handle is admitted on settimeout() alone, so gettimeout() may be
        # absent, may raise anything, or may return a non-number -- urllib3's
        # pyOpenSSL WrappedSocket, which inject_into_urllib3() installs as
        # conn.sock, defines settimeout and NO gettimeout.
        try:
            base_to = sock.gettimeout()
        except Exception:
            base_to = None
        # A usable ceiling is a finite, strictly positive real number. None
        # (blocking), 0 (non-blocking), a bool, NaN and any junk return all mean
        # "no ceiling to shorten", so the clamp stands down rather than guessing.
        if (isinstance(base_to, bool) or not isinstance(base_to, (int, float))
                or not math.isfinite(base_to) or base_to <= 0):
            base_to = None
        if base_to is None:
            sock = None

    chunks, size, got_raw = [], 0, False
    try:
        while True:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise RtevTimeout(
                        f"timed out after reading {size} bytes: the server was "
                        "still sending when the deadline expired")
                if sock is not None:
                    # Shorten this recv to the time left so a stalled body cannot
                    # block a whole socket timeout past the deadline. A healthy
                    # server delivering data every < left seconds is untouched;
                    # only a genuine stall trips it. base_to bounds it from above
                    # so the call can never LENGTHEN the socket's own timeout --
                    # when there is nothing left to shorten, leave it alone.
                    target = min(base_to, max(0.01, left))
                    if target < base_to:
                        try:
                            sock.settimeout(target)
                        except Exception:
                            # Same reasoning as the gettimeout probe: a handle
                            # that will not take a timeout costs us the clamp,
                            # not the read.
                            sock = None
            try:
                raw = read_some()
            except requests.exceptions.RequestException:
                # A recv that timed out on the clamp AT/PAST the deadline is a
                # wall-clock expiry, not a transport fault -- name it so, to
                # honor the docstring's hard bound. Off-deadline faults (a real
                # reset mid-stream) keep their retryable transport identity.
                if deadline is not None and time.monotonic() >= deadline:
                    raise RtevTimeout(
                        f"timed out after reading {size} bytes: the server "
                        "stalled the response body past the deadline") from None
                raise
            if not raw:
                break                       # true end of stream
            got_raw = True
            piece = inflate(raw)
            if not piece:
                continue                    # decoder is buffering; keep reading
            chunks.append(piece)
            size += len(piece)
            if size > cap:
                raise OrionError(
                    f"response exceeded {cap / (1024 * 1024):.4g} MB and was "
                    "abandoned")
        # got_raw gates this: a zero-byte body never started the inflater and
        # must not be misreported as truncated (a real truncation delivered
        # at least one byte).
        if inflater is not None and got_raw:
            try:
                tail = inflater.flush()
            except zlib.error as e:
                raise requests.exceptions.ContentDecodingError(
                    f"truncated gzip response: {e}") from e
            if tail:
                chunks.append(tail)
            # zlib does not raise on a truncated stream -- it just stops -- so
            # verify the decoder reached a trailer; otherwise a cut body would
            # surface as a confusing JSON error instead of a retryable
            # transport error. Errs strict on padding that looks like a
            # member header: refusing odd padding beats dropping events.
            if not member_done:
                raise requests.exceptions.ContentDecodingError(
                    "the gzip response ended mid-stream (truncated body)")
    finally:
        r.close()
    try:
        return b"".join(chunks).decode(r.encoding or "utf-8", errors="replace")
    except (LookupError, ValueError):
        # LookupError: the server named a charset Python does not know.
        # ValueError (which subsumes UnicodeError): it named one that cannot
        # decode -- a codec that rejects the attempt ("undefined", "idna") or
        # a name the codec lookup itself refuses (one containing NUL). Neither
        # may reach the caller raw.
        return b"".join(chunks).decode("utf-8", errors="replace")


def _fetch_once(s, host, node_id, log, cred, levels, start, limit, tz_offset,
                sources, last_first_record=0, last_total_count=0, timeout=90,
                deadline=None):
    """Single DataProvider round trip, with retries for transient failures.
    A 500 can mean a missing right, a bad NodeID, or a too-large response
    (see the response-size gotcha); the raised OrionError carries .http_status so
    fetch_events can disambiguate."""
    url = f"https://{host}/Orion/APM/Admin/RealTimeEventLogViewer/DataProvider.aspx"
    params = {
        "_dc": int(time.time() * 1000), "nodeId": node_id, "cred": cred,
        "cNodeId": node_id, "cCredId": cred, "cLog": log, "cLevels": levels,
        "cGrippedSources": sources,
        "cStart": start, "cLimit": limit,
        "cLastFirstRecord": last_first_record,
        "cLastTotalCount": last_total_count, "cTimeZoneOffset": tz_offset,
        "page": start // max(limit, 1) + 1, "start": start, "limit": limit,
        "callback": "cb",
    }

    last_err = None
    for attempt in range(RETRIES):
        if attempt:
            nap = 2 ** attempt                # 2s, 4s
            if deadline is not None:
                nap = min(nap, max(0.0, deadline - time.monotonic()))
            time.sleep(nap)
        # Never let retries push past the caller's overall deadline.
        this_timeout = timeout
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            this_timeout = min(timeout, max(1.0, left))
        try:
            # Adapter dispatch, same reason as the login flow: every byte
            # stays under the deadline.
            r = _send_bounded(s, "GET", url, this_timeout, deadline=deadline,
                              params=params)
            # Classify a redirect BEFORE reading the body: a malformed 302
            # body must not mask the session-expiry signal.
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location") or ""
                r.close()
                if "login" in location.lower():
                    raise SessionExpired(
                        "the Orion session is no longer authenticated (the "
                        "endpoint redirected to the login page)")
                raise OrionError(
                    f"the endpoint returned an unexpected HTTP {r.status_code} "
                    f"redirect to {location[:120] or '(no Location)'}. This is "
                    "not a session expiry, so re-authenticating would not help.")
            body = _read_bounded(r, deadline)
        except RtevTimeout:
            raise                       # the caller's budget is spent; do not retry
        except requests.exceptions.RequestException as e:
            # Connection reset, DNS blip, read timeout: worth another try.
            last_err = OrionError(
                f"request to {host} failed: {type(e).__name__}: "
                f"{' '.join(str(e).split())[:140]}")
            continue
        except OSError as e:
            # Bare OSError (RequestException subclasses it but does not cover
            # this): requests' cert_verify on a missing verify=/
            # REQUESTS_CA_BUNDLE path. Deterministic, so retrying cannot help.
            raise OrionError(f"cannot start the request to {host}: "
                             f"{' '.join(str(e).split())[:140]}") from e

        if r.status_code in RETRY_STATUS:
            last_err = OrionError(
                f"HTTP {r.status_code} from {host}: {_html_summary(body, r.status_code)}")
            continue

        if r.status_code != 200:
            hint = ""
            if r.status_code == 500:
                hint = (" -- a 500 here means a missing Real-Time Event Log "
                        "Viewer right, a bad NodeID, or a too-large response")
            err = OrionError(
                f"HTTP {r.status_code}: {_html_summary(body, r.status_code)}{hint}")
            err.http_status = r.status_code
            raise err

        body = body.strip()
        if not body.startswith("cb("):
            if _looks_like_login_page(body):
                raise SessionExpired(
                    "the Orion session is no longer authenticated (the endpoint "
                    "returned the login page)")
            raise OrionError(
                f"unexpected non-JSONP response ({len(body)} bytes): "
                f"{_html_summary(body, r.status_code)}")

        try:
            payload = json.loads(re.sub(r"\);?$", "", body[3:]))
        except (ValueError, RecursionError) as e:
            # RecursionError: absurdly nested JSON; not a ValueError, and it
            # must not escape the OrionError contract (or take down a whole
            # search_many batch for one malformed node).
            raise OrionError(
                f"could not parse the JSONP payload ({len(body)} bytes): {e}") from e
        # The endpoint is undocumented and may change shape on any upgrade, so
        # assert the one thing every caller downstream assumes rather than
        # letting `null` or a bare list surface as an AttributeError.
        if not isinstance(payload, dict):
            raise OrionError(
                "unexpected JSONP payload: expected a JSON object, got "
                f"{type(payload).__name__}")
        return payload

    timeout_err = RtevTimeout(
        f"ran out of time contacting {host} before a response completed "
        "(poll timeout reached during retries)")
    if deadline is not None and time.monotonic() > deadline:
        # Out of budget: the timeout is the honest verdict even when the last
        # attempt surfaced as a socket error.
        raise timeout_err
    if last_err:
        raise last_err
    raise timeout_err


# Appended to both timeout messages; the Security-log caveat is in the README.
_TIMEOUT_HINT = (" -- some logs time out server-side under the inherited "
                 "credential (README: the Security-log gotcha)")


def _probe_ok(s, host, node_id, log, cred, levels, tz_offset, sources,
              deadline):
    """One minimal fresh-session request to tell the two 500s apart. Returns
    True (probe passed: the original 500 was the size ceiling), False (probe
    500s too: rights or NodeID), or None (probe inconclusive -- login failed
    or broke some other way; the caller re-raises the original error).
    Raises RtevTimeout only when the budget ran out mid-probe."""
    probe = OrionSession(s.orion_host, s.orion_user, s._password,
                         verify=s.verify)
    try:
        _, _, authed = _do_login(probe, s.orion_host, s.orion_user,
                                 s._password, deadline=deadline)
        if not authed:
            return None
        _fetch_once(probe, host, node_id, log, cred, levels, 0, PROBE_LIMIT,
                    tz_offset, sources, deadline=deadline)
        return True
    except RtevTimeout:
        raise                               # out of budget is its own verdict
    except requests.exceptions.SSLError:
        return None                         # outside the hierarchy; stay quiet
    except OrionError as pe:
        if getattr(pe, "http_status", None) == 500:
            return False
        return None
    finally:
        probe.close()


def fetch_events(s, host, node_id, log="System", cred=-3, levels=31,
                 start=0, limit=200, tz_offset=0, sources='["0-999999"]',
                 last_first_record=0, last_total_count=0,
                 poll_timeout=90, poll_interval=1.5, request_timeout=90,
                 _allow_over_max=False):
    """One page of the live Windows event log, via the agent's async job.

    RTEV is async: the first request dispatches an agent job and returns
    JobPollingStatus=1 with no events. This re-issues the same request until
    a terminal status (Finished 4 / Error 3) OR the first non-empty Events
    list arrives -- so it never returns a pending-empty page as an empty log,
    which is the invariant callers rely on. The cred=-3 / levels=31 / sources
    defaults, the over-fetch, and the window mechanics are described below.

    poll_timeout is a real wall-clock bound on this call. Raises RtevTimeout
    if the job never becomes terminal; ResponseTooLarge when the server
    refuses to serialize the response and a fresh-session probe rules out a
    rights/NodeID problem (OrionSession callers with limit > PROBE_LIMIT;
    others get the raw 500); OrionError with the server's ErrorMessage on a
    status-3 failure.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise OrionError(f"limit must be a positive integer, got {limit!r}")
    if limit > MAX_LIMIT and not _allow_over_max:
        raise OrionError(f"limit {limit} exceeds MAX_LIMIT ({MAX_LIMIT}); "
                         "larger responses hit the server's ~4 MB ceiling")
    if not isinstance(start, int) or isinstance(start, bool) or start < 0:
        raise OrionError(f"start must be a non-negative integer, got {start!r}")
    # Every seconds-valued parameter, not just poll_timeout: all three feed the
    # same deadline and sleep arithmetic, and guarding them one at a time is
    # how this class of bug kept coming back (see _check_seconds). REBIND to
    # what it returns -- the coerced float is the point, since time.sleep(),
    # Thread.join() and the adapter's timeout= all reject a Fraction or a
    # numpy.float32 that is otherwise a perfectly valid number of seconds.
    poll_timeout = _check_seconds("poll_timeout", poll_timeout)
    poll_interval = _check_seconds("poll_interval", poll_interval)
    request_timeout = _check_seconds("request_timeout", request_timeout)

    deadline = time.monotonic() + poll_timeout
    reauthed = False
    while True:
        try:
            j = _fetch_once(s, host, node_id, log, cred, levels, start, limit,
                            tz_offset, sources, last_first_record,
                            last_total_count, timeout=request_timeout,
                            deadline=deadline)
        except RtevTimeout as e:
            # Re-raise with the log/node context the caller needs.
            raise RtevTimeout(
                f"RTEV job for log {log!r} on node {node_id} did not complete "
                f"within {poll_timeout}s: {e}.{_TIMEOUT_HINT}") from e
        except SessionExpired:
            # Recover once, silently, if this session knows its credentials.
            if reauthed or not hasattr(s, "reauth"):
                raise
            reauthed = True
            print("note: Orion session expired; renewing the session",
                  file=sys.stderr)
            if not s.reauth(deadline=deadline):
                raise
            continue
        except OrionError as e:
            # Disambiguate the two 500s with a minimal probe.
            if (getattr(e, "http_status", None) == 500
                    and limit > PROBE_LIMIT and isinstance(s, OrionSession)):
                verdict = _probe_ok(s, host, node_id, log, cred, levels,
                                    tz_offset, sources, deadline)
                if verdict:
                    raise ResponseTooLarge(
                        f"the server refused to serialize {limit} rows for "
                        f"log {log!r} on node {node_id} (the byte ceiling -- "
                        "see MAX_LIMIT); retry a smaller limit on a fresh "
                        "session, which search() does automatically") from e
                if verdict is False:
                    raise OrionError(
                        f"HTTP 500 for log {log!r} on node {node_id} even at "
                        f"limit={PROBE_LIMIT}: the account lacks the "
                        "Real-Time Event Log Viewer right or the NodeID is "
                        "wrong") from e
            raise                           # inconclusive probe: original error

        status = _wire_int(j.get("JobPollingStatus"))
        events = j.get("Events")
        if events is None:
            events = []
        err = j.get("ErrorMessage")
        # Shape guard: a string or object here would be iterated as characters
        # or keys deep inside the paging loop.
        if not isinstance(events, list):
            raise OrionError("unexpected response shape: Events is "
                             f"{type(events).__name__}, expected a list")

        # Status 3 is fatal even with events; an ErrorMessage with no events
        # is fatal too; an ErrorMessage alongside events on a non-terminal
        # status is a partial read -- keep the data.
        if status == JOB_ERROR or (err and not events):
            msg = as_text(err).strip() or "JobPollingStatus=Error"
            explain = _explain(msg)
            raise OrionError(f"RTEV error for log {log!r} on node {node_id}: "
                             + (f"{msg} -- {explain}" if explain else msg))

        if status == JOB_DONE or events:
            return j

        if time.monotonic() > deadline:
            raise RtevTimeout(
                f"RTEV job for log {log!r} on node {node_id} did not complete "
                f"within {poll_timeout}s (last JobPollingStatus={status})."
                f"{_TIMEOUT_HINT}")
        left = deadline - time.monotonic()
        if left > 0:
            time.sleep(min(poll_interval, left))


@dataclasses.dataclass
class _SweepState:
    """Mutable sweep state threaded through _sweep/_ingest across downsize
    restarts and deep rounds. A dataclass so a mistyped field is an
    AttributeError at the typo, not a silently new dict key."""
    limit: int
    seen: set = dataclasses.field(default_factory=set)
    hits: list = dataclasses.field(default_factory=list)
    last_first: int = 0
    last_total: int = 0
    downsizes: int = 0
    resized: bool = False
    over_max_ok: bool = False
    exhausted: bool = False
    partial: bool = False
    stalled: bool = False
    renewed: bool = False


def _check_seconds(name, value):
    """Validate a public seconds-valued parameter: a positive finite real.

    One helper for ALL of them (poll_timeout, poll_interval, request_timeout)
    on purpose. Guarding them individually is how this kept recurring:
    poll_timeout was validated while the two siblings feeding the same deadline
    and sleep arithmetic were left open, so the next sweep found them. A
    non-finite value makes the deadline NaN, and every comparison against NaN
    is False -- so neither the timeout exit nor the sleep fires and the poll
    becomes a zero-backoff request storm; a negative one reaches time.sleep()
    as a bare ValueError.

    numbers.Real, not isinstance(x, (int, float)): a Fraction or a numpy
    scalar is a perfectly good number of seconds, and admitting only float/int
    and their subclasses accepts numpy.float64 (which subclasses float) while
    rejecting numpy.float32 and numpy.int64 -- so the same value would work or
    fail depending on an array's dtype. bool is excluded: True is not 1 second.

    RETURNS THE VALUE AS A float, and callers must use what it returns.
    Accepting a wider set than the consumers can take would just move the
    failure downstream: time.sleep(), Thread.join() and the adapter's timeout=
    all reject anything that is not a float/int subclass, so a Fraction or a
    numpy.float32 passed validation and then raised a bare TypeError from
    three different places. Validating a value and handing on the original is
    a promise the callee cannot keep; coercing here is what makes the check
    mean something.
    """
    bad = f"{name} must be a positive, finite number of seconds, got {value!r}"
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise OrionError(bad)
    try:
        # An exotic Real may not survive the conversion, or may not order
        # against 0; either way it is unusable as a deadline.
        seconds = float(value)
    except (TypeError, ValueError, OverflowError) as e:
        raise OrionError(bad) from e
    if not math.isfinite(seconds) or seconds <= 0:
        raise OrionError(bad)
    return seconds


def _compile_pattern(pattern):
    """Compile the user's regex, wrapping every compile-time failure class:
    re.compile raises bare OverflowError on a{2**32} and RecursionError on
    deep nesting -- neither is an re.error, and OverflowError is not even a
    RuntimeError, so unwrapped it would defeat the catch-all."""
    try:
        return re.compile(pattern, re.I)
    except (re.error, OverflowError, RecursionError) as e:
        raise OrionError(f"invalid regex {pattern!r}: {e}") from e


def _estimate_kb_per_row(payload, rows):
    """Serialized KB per event row for one parsed page, or None."""
    if not rows:
        return None
    return len(json.dumps(payload)) / 1024 / rows


def _ingest(events, rx, state):
    """Dedupe one page's rows into state and collect regex matches."""
    for e in events:
        if not isinstance(e, dict):
            continue
        num = _rec_int(e)
        if num is not None:
            # Same identity the anchor uses, so the two cannot disagree.
            rec = ("rec", num)
        else:
            # No usable identity: a composite wide enough that two genuinely
            # different events (same-millisecond logons, say) do not collapse;
            # str() keeps an unhashable nested value from crashing the set.
            rec = ("composite", str(e.get("TimeGeneratedUtc")),
                   str(e.get("EventCode")), str(e.get("SourceName")),
                   str(e.get("User")), str(e.get("ComputerName")),
                   str(e.get("Message")))
        if rec in state.seen:
            continue
        state.seen.add(rec)
        # Coerce before matching: no wire field is contractually a string.
        msg = as_text(e.get("Message"))
        src = as_text(e.get("SourceName"))
        # The FULL field is searched, deliberately: see the hazard note above
        # SEARCH_TEXT_CAP's former home -- truncating here fabricates matches
        # at the cut and turns fast successes into non-terminating searches.
        if rx.search(msg) or rx.search(src):
            state.hits.append({
                "utc": ms_to_utc(e.get("TimeGeneratedUtc")),
                "code": e.get("EventCode"), "src": e.get("SourceName"),
                "user": e.get("User"),
                "msg": " ".join(msg.split())[:200],
            })


def _redispatch(s):
    """Fresh login so the next request dispatches a NEW server job, which
    extends the server's tracked window. Note this is NOT
    needed to change cLimit -- that takes effect on any request -- so the
    downsize and auto-limit callers use it only for the clean restart and
    the extra depth. Returns True on success, False on ANY
    failure: reauth can raise on a network blip (OrionError) or on a bad TLS
    trust-store path (bare OSError, from requests' own cert handling), and
    every caller already has a correct False branch.

    Bounded by LOGIN_TIMEOUT (the same default login() uses): without a
    deadline the re-login inherits none, and a server dribbling the login
    page would hold the sweep open until the 64 MB body cap -- hours."""
    if not hasattr(s, "reauth"):
        return False
    try:
        return s.reauth(deadline=time.monotonic() + LOGIN_TIMEOUT)
    except (OrionError, OSError):
        return False


# _sweep helper verdicts: what to do after a recoverable event.
_RESTART, _PARTIAL, _RAISE = "restart", "partial", "raise"


def _handle_too_large(s, st):
    """Downsize policy for a ResponseTooLarge. Returns _RESTART (limit
    halved, job re-dispatched -- re-walk from page 0, dedupe absorbs it;
    the caller must resync its reauth_count snapshot), _PARTIAL (keep what
    was gathered and stop), or _RAISE (nothing was gathered and either the
    downsize budget is spent or the re-dispatch login failed; the caller
    re-raises the original error)."""
    if st.downsizes >= 3 or st.limit <= PROBE_LIMIT:
        return _RAISE if not st.seen else _PARTIAL
    st.downsizes += 1
    old, st.limit = st.limit, max(PROBE_LIMIT, st.limit // 2)
    st.resized = True
    print(f"note: response too large at limit={old}; restarting the sweep "
          f"at {st.limit} (depth is kept by the anchor).", file=sys.stderr)
    if _redispatch(s):
        return _RESTART
    return _RAISE if not st.seen else _PARTIAL


def _maybe_autosize(s, st, page_payload, n_events):
    """After page 1 in auto-limit mode: re-size the page limit to the byte
    budget using the measured bytes-per-row. Returns True when the job was
    re-dispatched at the new size (the caller re-reads page 1; dedupe
    absorbs the re-walk); reverts and returns False if re-login failed."""
    kbrow = _estimate_kb_per_row(page_payload, n_events)
    target = None
    if kbrow:
        target = max(PROBE_LIMIT,
                     min(int(SAFE_RESPONSE_MB * 1024 / (4 * kbrow)),
                         AUTO_LIMIT_CAP))
    if not target or abs(target - st.limit) <= st.limit // 4:
        return False
    old, st.limit = st.limit, target
    st.resized = True
    # Only the auto-limit path may exceed MAX_LIMIT -- its size is derived
    # from measured bytes-per-row, not guessed.
    st.over_max_ok = target > MAX_LIMIT
    print(f"note: auto-limit {old} -> {target} (~{kbrow:.2f} KB/row).",
          file=sys.stderr)
    if _redispatch(s):
        return True
    st.limit, st.resized, st.over_max_ok = old, False, False
    return False


def _sweep(s, host, node_id, rx, log, max_pages, auto_limit, st,
           floor_note=True, **kw):
    """One paging pass; mutates st (including its completeness flags).
    Returns True unless the pass failed mid-way or the anchor stalled."""
    def partial_warning(page, exc):
        print(f"WARNING: stopped at page {page + 1}/{max_pages} after "
              f"{len(st.seen)} events: {exc}\n"
              "  Results below are PARTIAL.", file=sys.stderr)

    reauths = getattr(s, "reauth_count", 0)
    exhausted = failed = stalled = False
    p = 0
    while p < max_pages:
        limit = st.limit
        try:
            j = fetch_events(s, host, node_id, log=log, start=p * limit,
                             limit=limit, last_first_record=st.last_first,
                             last_total_count=st.last_total,
                             _allow_over_max=st.over_max_ok, **kw)
        except ResponseTooLarge as e:
            action = _handle_too_large(s, st)
            if action == _RESTART:
                reauths = getattr(s, "reauth_count", 0)
                p = 0                       # dedupe absorbs the re-walk
                continue
            if action == _RAISE:
                raise
            failed = True
            partial_warning(p, e)
            break
        except (OrionError, TimeoutError) as e:
            if not st.seen:
                raise                       # nothing was ever going to work
            failed = True
            partial_warning(p, e)
            break

        now_reauths = getattr(s, "reauth_count", 0)
        if now_reauths != reauths:
            reauths = now_reauths
            # An expiry re-login restarted the paging window; cStart cannot be
            # rewound, so depth already covered may be re-walked -- and, worse,
            # cStart may now point PAST a shallower fresh window, whose empty
            # page would otherwise read as end-of-data. Past page 0 (where
            # there was depth to lose) that makes any later exhaustion verdict
            # untrustworthy, so flag it: see the exhaustion rule below.
            if p > 0:
                st.renewed = True
                print("WARNING: the Orion session was renewed mid-sweep, "
                      "which restarts the server-side paging window. Some "
                      "depth may be re-walked; re-run for a "
                      "guaranteed-complete sweep.", file=sys.stderr)

        events = j.get("Events") or []
        if not events:
            exhausted = True                # the server's only end-of-data signal
            break

        # Anchor on the highest RecordNumber seen; a pinned anchor walls
        # paging out early: the anchor is what reaches deeper history.
        usable = [n for n in (_rec_int(e) for e in events) if n is not None]
        if usable:
            st.last_first = max([st.last_first] + usable)
        else:
            stalled = True
            print(f"WARNING: page {p + 1} returned {len(events)} rows, none "
                  "carrying a usable RecordNumber, so paging cannot advance "
                  "past this point. Results are INCOMPLETE.", file=sys.stderr)
        st.last_total = _wire_int(j.get("TotalEventsCount")) or st.last_total
        _ingest(events, rx, st)
        if stalled:
            break                           # rows above are kept; depth is not

        if auto_limit and p == 0 and not st.resized:
            if _maybe_autosize(s, st, j, len(events)):
                reauths = getattr(s, "reauth_count", 0)
                continue                    # p stays 0: fresh job, new size
        p += 1

    # After a mid-sweep renewal the server's empty page is not end-of-data --
    # it can simply mean cStart ran past a restarted, shallower window -- so
    # exhaustion cannot be claimed. (deep mode narrows this further, below.)
    st.exhausted = exhausted and not st.renewed
    st.partial = st.partial or failed
    st.stalled = st.stalled or stalled
    if not exhausted and not failed and not stalled and floor_note:
        # The page budget ran out before the log did: a floor, not an answer.
        print(f"note: stopped at the {max_pages}-page limit with "
              f"{len(st.seen)} events, before the log was exhausted. "
              "Results are a FLOOR; raise --pages for a deeper search.",
              file=sys.stderr)
    return not failed and not stalled


def search(s, host, node_id, pattern, log="System", max_pages=30, limit=200,
           auto_limit=False, deep=False, **kw):
    """Page back through the live log. Returns a SearchResult, which unpacks
    as the historical (hits, unique_events_seen) two-tuple and additionally
    carries the completeness verdicts (exhausted / partial / stalled /
    renewed) that
    are also printed to stderr.

    Threads the paging cursor (highest RecordNumber -> cLastFirstRecord, held
    while cStart advances), exactly as the RTEV grid does. Stops on the
    server's EMPTY page -- its only reliable end-of-data signal (unless the
    session was renewed mid-sweep; see SearchResult); duplicate
    pages mid-sweep are normal and never end the sweep. A failure on
    the first page is fatal; on a later page the partial results are returned
    with partial=True. A ResponseTooLarge on any page (auto_limit or not)
    halves the limit and re-dispatches on a fresh login, at most 3 times, so
    large pulls degrade instead of failing. The library default of 30 pages
    suits sweeps; the CLI defaults to 6 for interactive quick checks.

    auto_limit=True: after the first page, re-sizes the page limit to fit
    SAFE_RESPONSE_MB from the measured bytes-per-row, then restarts the
    sweep on a fresh login so the re-walk starts from page 0.

    deep=True: re-sweeps on a fresh login while new unique events keep
    arriving (each dispatch extends the server's tracked window),
    up to DEEP_MAX_ROUNDS rounds. Reaches materially more history on busy
    logs.
    """
    rx = _compile_pattern(pattern)
    st = _SweepState(limit=limit)
    rounds = DEEP_MAX_ROUNDS if deep else 1
    # Deep mode only reaches the whole log when a round comes back with
    # nothing new. Every other exit -- the round cap, a failed re-login, a
    # failed sweep -- left more history reachable, so `converged` stays False
    # and clears the exhausted verdict below. A single (non-deep) sweep's own
    # end-of-data verdict stands on its own.
    converged = not deep
    for rnd in range(rounds):
        before = len(st.seen)
        if rnd and not _redispatch(s):
            print("WARNING: deep mode stopped early: could not re-login for "
                  f"round {rnd + 1}.\n  Results below are PARTIAL.",
                  file=sys.stderr)
            st.partial = True
            break
        ok = _sweep(s, host, node_id, rx, log, max_pages, auto_limit, st,
                    floor_note=not deep, **kw)
        if not deep:
            break
        gained = len(st.seen) - before
        print(f"note: deep round {rnd + 1}: {gained} new unique events "
              f"({len(st.seen)} total).", file=sys.stderr)
        if not ok:
            break                       # _sweep already flagged partial/stalled
        if gained == 0:
            converged = True            # a fresh dispatch found nothing more
            break
    else:
        if deep:
            print(f"note: deep mode hit its {DEEP_MAX_ROUNDS}-round cap while "
                  "still finding new events; more history may remain.",
                  file=sys.stderr)
    if deep:
        # Exhaustion needs convergence too -- see the comment above the loop.
        st.exhausted = st.exhausted and converged
        if not st.exhausted:
            print(f"note: deep sweep ended at {len(st.seen)} unique events "
                  "with more history still reachable; results are a FLOOR.",
                  file=sys.stderr)
    return SearchResult(hits=st.hits, scanned=len(st.seen),
                        exhausted=st.exhausted, partial=st.partial,
                        stalled=st.stalled, renewed=st.renewed)


def search_many(host, user, password, node_ids, pattern, log="System",
                max_pages=6, limit=200, workers=4, insecure=False, **kw):
    """Run search() against several nodes concurrently. Returns
    {node_id: {"hits": [...], "scanned": n, "exhausted": bool,
    "partial": bool, "stalled": bool, "renewed": bool, "complete": bool}},
    with an {"error": "..."} value instead for a node that failed -- one node
    never blocks the others.

    One worker thread and one authenticated session per node: server-side
    jobs are tracked per session+node+log, so distinct nodes never contend
    and each endpoint agent still sees strictly sequential work.
    Threads, not processes -- the workload is network-bound. stderr notes
    from concurrent sweeps may interleave. Ctrl-C cancels nodes that have
    not started; nodes already running complete their current pull before
    the process exits.
    """
    _compile_pattern(pattern)               # fail fast, before any threads
    # Materialize first: node_ids is documented as "a node list", so a caller
    # may reasonably stream one (a generator/map). len() and the results dict
    # would otherwise raise a bare TypeError -- and the unhashable case only
    # after a session was already opened.
    try:
        node_ids = list(node_ids)
    except TypeError as e:
        raise OrionError(f"node_ids must be an iterable of Orion NodeIDs: {e}") from e
    for n in node_ids:
        # hash(), not isinstance(Hashable): the ABC only checks that __hash__ is
        # present, so a tuple containing a list passes it and then raises from
        # the results dict -- after a session was opened and a sweep already ran.
        try:
            hash(n)
        except TypeError as e:
            raise OrionError(
                f"node_ids must be hashable Orion NodeIDs, got {n!r}: {e}") from e

    def pull(node_id):
        try:
            s, _, authed = connect(host, user, password, insecure=insecure)
        except (OrionError, TimeoutError) as e:
            return node_id, {"error": str(e)}
        try:
            if not authed:
                return node_id, {"error": "login failed -- no auth cookie "
                                          "(LOCAL Orion accounts only)"}
            res = search(s, host, node_id, pattern, log=log,
                         max_pages=max_pages, limit=limit, **kw)
            # as_dict() is the single source of this shape, so adding a verdict
            # to SearchResult cannot leave the multi-node path silently stale.
            return node_id, res.as_dict()
        except (OrionError, TimeoutError) as e:
            return node_id, {"error": str(e)}
        finally:
            s.close()

    results = {}
    workers = max(1, min(workers, len(node_ids)))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(pull, n) for n in node_ids]
    try:
        for f in concurrent.futures.as_completed(futures):
            node_id, res = f.result()
            results[node_id] = res
    except BaseException:
        # Ctrl-C or a worker's bug-class exception: never leave the pool
        # running behind the raise.
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:                   # Python < 3.9: no cancel_futures
            for f in futures:
                f.cancel()
            pool.shutdown(wait=False)
        raise
    pool.shutdown(wait=True)
    return results


# Events whose timestamp did not parse sort last rather than crashing the sort:
# a naive datetime cannot be compared with the timezone-aware ones.
_NO_TIME = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)


def sort_hits(hits, reverse=False):
    """Sort hits oldest-first by timestamp, with unparseable timestamps last.

    Use this rather than sorting on h["utc"] directly: that field is None when
    a timestamp did not parse, and substituting a naive datetime.min raises
    TypeError against the timezone-aware values beside it.
    """
    return sorted(hits, key=lambda h: h.get("utc") or _NO_TIME, reverse=reverse)


def format_hit(h):
    """Render one match. Every field is optional in the wire data -- User is
    routinely null, and a truncated or malformed row can be missing any of the
    rest -- so nothing here may assume a value is present."""
    utc = h.get("utc")
    # Pad to the exact width of a rendered stamp so the id= column stays aligned.
    stamp = f"{utc:%Y-%m-%d %H:%M:%S}Z" if utc else "(no timestamp)      "
    code = h.get("code")
    code = str(code) if code is not None else "-"
    user = as_text(h.get("user")) or "-"
    return (f"  {stamp}  id={code:<6} user={user:<12} "
            f"{as_text(h.get('msg'))[:110]}")


def main():
    # Event messages can carry characters the terminal encoding cannot
    # represent; degrade to replacement characters instead of dying
    # mid-print. Here rather than at import so library users keep their own
    # stdout configuration (the example CLIs do the same for themselves).
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(
        description="Search the LIVE Windows event log on an Orion "
                    "agent-managed node. No browser required.",
        epilog="Credentials resolve in order: CLI flag, then ORION_* "
               "environment variable, then --env file, then an interactive "
               "password prompt. There is deliberately no --password flag; "
               "passwords on a command line leak via process lists and "
               "shell history.")
    ap.add_argument("node_id",
                    help="Orion NodeID of the target node, or a comma-"
                         "separated list (e.g. 1234,1235) for a multi-node "
                         "pull on bounded worker threads")
    ap.add_argument("pattern", help="regex matched against Message and SourceName")
    ap.add_argument("--log", default="System",
                    help="System, Application, Security, ... (default: System)")
    ap.add_argument("--pages", type=int, default=6,
                    help="maximum pages to request; paging ends when the "
                         "server runs out of events, and warns if this limit "
                         "is hit first (default 6)")
    ap.add_argument("--limit", type=int, default=200,
                    help=f"rows requested per page, 1-{MAX_LIMIT}; the server "
                         "returns roughly 4x this many (default 200)")
    ap.add_argument("--poll-timeout", type=float, default=90, metavar="SEC",
                    help="seconds to wait for one page's agent job before "
                         "giving up (default 90; long enough to surface a "
                         "server-side WMI timeout as its own error)")
    ap.add_argument("--deep", action="store_true",
                    help="re-sweep on fresh logins while new events keep "
                         "arriving; reaches deeper history on busy logs")
    ap.add_argument("--auto-limit", action="store_true",
                    help="size pages to the server's ~4 MB response ceiling "
                         "using the first page's measured bytes-per-row")
    ap.add_argument("--workers", type=int, default=4,
                    help="worker threads for a multi-node pull (default 4)")
    ap.add_argument("--insecure", action="store_true",
                    help="proceed even if the TLS certificate cannot be "
                         "verified (sends your password to an unauthenticated "
                         "server -- prefer fixing the trust store)")
    ap.add_argument("--host", help="Orion web console host, e.g. orion.example.com")
    ap.add_argument("--user", help="LOCAL Orion account (SSO/IdP accounts cannot "
                                   "authenticate on this path)")
    ap.add_argument("--env", metavar="FILE",
                    help="optional KEY=VALUE file supplying ORION_HOST / "
                         "ORION_USER / ORION_PASSWORD")
    a = ap.parse_args()

    try:
        node_ids = [int(x) for x in a.node_id.split(",") if x.strip()]
    except ValueError:
        ap.error(f"node_id must be an integer or a comma-separated list of "
                 f"integers, got {a.node_id!r}")
    node_ids = list(dict.fromkeys(node_ids))    # dedupe, keeping input order
    if not node_ids or any(n <= 0 for n in node_ids):
        ap.error("every node_id must be a positive Orion NodeID")
    if a.workers < 1:
        ap.error("--workers must be at least 1")
    if a.pages < 1:
        ap.error("--pages must be at least 1")
    if not 1 <= a.limit <= MAX_LIMIT:
        ap.error(f"--limit must be between 1 and {MAX_LIMIT}")
    # math.isfinite rejects inf/nan, which argparse's type=float accepts and
    # which would otherwise surface as a bare OverflowError deep in a join().
    if not math.isfinite(a.poll_timeout) or a.poll_timeout <= 0:
        ap.error("--poll-timeout must be a positive, finite number of seconds")

    # Validate the pattern BEFORE prompting for a password: a bad regex should
    # not cost the user a login round trip and a credential prompt first.
    try:
        _compile_pattern(a.pattern)
    except OrionError as e:
        # A raw traceback here is the one thing bad input must never produce.
        ap.error(str(e))

    try:
        envfile = load_env(a.env) if a.env else {}
    except OrionError as e:
        sys.exit(str(e))

    host = resolve(a.host, envfile, "ORION_HOST")
    user = resolve(a.user, envfile, "ORION_USER")
    password = resolve(None, envfile, "ORION_PASSWORD", "ORION_PASS")
    if not host or not user:
        sys.exit("need an Orion host and user: pass --host/--user, set "
                 "ORION_HOST/ORION_USER, or supply them via --env FILE")
    if not password:
        if not sys.stdin.isatty():
            sys.exit("no password: set ORION_PASSWORD, put it in an --env "
                     "file, or run interactively to be prompted")
        try:
            password = getpass.getpass(f"Orion password for {user}@{host}: ")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nno password entered")
        if not password:
            sys.exit("no password entered")

    sweep_kw = dict(log=a.log, max_pages=a.pages, limit=a.limit,
                    poll_timeout=a.poll_timeout, auto_limit=a.auto_limit,
                    deep=a.deep)
    if len(node_ids) == 1:
        try:
            s, resp, authed = connect(host, user, password, insecure=a.insecure)
        except OrionError as e:
            sys.exit(str(e))
        if not authed:
            sys.exit(f"login failed (HTTP {resp.status_code}) -- no auth "
                     "cookie. Check the password, and note the account must "
                     "be a LOCAL Orion account; SSO/IdP accounts cannot "
                     "authenticate here.")
        print(f"authenticated as {user} on {host}")

        try:
            hits, scanned = search(s, host, node_ids[0], a.pattern, **sweep_kw)
        except (OrionError, TimeoutError) as e:
            sys.exit(f"RTEV query failed: {e}")
        except KeyboardInterrupt:
            sys.exit("\ninterrupted")

        print(f"scanned {scanned} unique events in {a.log}; "
              f"{len(hits)} matches\n")
        for h in sort_hits(hits):
            print(format_hit(h))
    else:
        try:
            results = search_many(host, user, password, node_ids, a.pattern,
                                  workers=a.workers, insecure=a.insecure,
                                  **sweep_kw)
        except (OrionError, TimeoutError) as e:
            sys.exit(f"RTEV query failed: {e}")
        except KeyboardInterrupt:
            sys.exit("\ninterrupted")

        failures = 0
        for node_id in node_ids:            # input order, not completion order
            res = results.get(node_id, {"error": "no result returned"})
            if "error" in res:
                failures += 1
                print(f"== node {node_id}: FAILED: {res['error']}\n")
                continue
            print(f"== node {node_id}: scanned {res['scanned']} unique "
                  f"events in {a.log}; {len(res['hits'])} matches")
            for h in sort_hits(res["hits"]):
                print(format_hit(h))
            print()
        if failures == len(node_ids):
            sys.exit("every node failed")
    # Flush inside main so a broken pipe is caught by the __main__ handler
    # rather than by the interpreter's shutdown flush, which prints.
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # `orionRTEVpull.py ... | head` closes the pipe early; exit quietly instead
        # of printing a traceback. Devnull the fd so the interpreter's own
        # flush-on-exit cannot raise a second one.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
