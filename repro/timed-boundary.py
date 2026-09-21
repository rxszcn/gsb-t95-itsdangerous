"""一条时间戳 token 在 61 种形状与调用下各给什么读数。
跑法：PYTHONPATH=src .venv/bin/python repro/timed-boundary.py
"""



import time
from datetime import datetime, timezone

from itsdangerous import (
    BadData,
    BadTimeSignature,
    SignatureExpired,
    TimestampSigner,
    TimedSerializer,
    URLSafeTimedSerializer,
)
from itsdangerous.encoding import base64_encode, int_to_bytes

KEY = "secret-key"
MAX_OK = 253_402_300_799  # 9999-12-31T23:59:59Z, last representable timestamp
OVER_1 = MAX_OK + 1  # ValueError: year 10000 is out of range
MS_CLOCK = 1_750_000_000_123  # a get_timestamp() that returns milliseconds
HUGE = 2**62  # OSError [Errno 75] Value too large for defined data type
MAX_I64 = 2**63  # OverflowError: timestamp out of range for platform time_t

ANY = object()
rows = []


def dt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def tok(value=b"value", ts=MAX_OK, key=KEY):
    """Hand-built token: value . base64(int_to_bytes(ts)) . sig  (never uses sign())."""
    s = TimestampSigner(key)
    body = value + b"." + base64_encode(int_to_bytes(ts))
    return body + b"." + s.get_signature(body)


def stok(serializer, obj, ts):
    """Hand-built TimedSerializer-shaped token for a serializer instance."""
    payload = serializer.dump_payload(obj)
    body = payload + b"." + base64_encode(int_to_bytes(ts))
    signer = serializer.make_signer()
    return body + b"." + signer.get_signature(body)


def expect_bad(name, get, payload=ANY):
    """Out-of-range timestamp must surface as BadTimeSignature, not SignatureExpired
    (its expiry cannot be computed) and not a raw ValueError/OSError/OverflowError."""
    try:
        got = get()
    except BadData as e:
        ok = (
            isinstance(e, BadTimeSignature)
            and (payload is ANY or getattr(e, "payload", None) == payload)
            and not isinstance(e, SignatureExpired)
        )
        rows.append((name, ok, f"{type(e).__name__} payload={getattr(e, 'payload', None)!r}"))
        return
    except BaseException as e:  # noqa: BLE001
        rows.append((name, False, f"RAW {type(e).__name__}: {str(e)[:56]}"))
        return
    rows.append((name, False, f"no error, value={got!r}"[:88]))


def expect_value(name, get, expected):
    try:
        got = get()
    except BaseException as e:  # noqa: BLE001
        rows.append((name, False, f"raised {type(e).__name__}: {str(e)[:56]}"))
        return
    rows.append((name, got == expected, f"{got!r}"[:88]))


def expect_expired_dated(name, get, ts):
    try:
        got = get()
    except SignatureExpired as e:
        rows.append(
            (
                name,
                e.date_signed == dt(ts) and e.payload == b"value",
                f"SignatureExpired date_signed={e.date_signed!r}",
            )
        )
        return
    except BaseException as e:  # noqa: BLE001
        rows.append((name, False, f"raised {type(e).__name__}: {str(e)[:56]}"))
        return
    rows.append((name, False, f"no error, value={got!r}"[:80]))


signer = TimestampSigner(KEY)
tser = TimedSerializer(KEY)
utser = URLSafeTimedSerializer(KEY)


for tag, tsv in (("over1", OVER_1), ("ms", MS_CLOCK), ("huge", HUGE), ("i64", MAX_I64)):
    expect_bad(
        f"A-{tag}-return_timestamp",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), return_timestamp=True),
    )
    expect_bad(
        f"A-{tag}-future-max_age",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), max_age=60),
    )
    expect_bad(
        f"A-{tag}-negmaxage",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), max_age=-(2 ** 63)),
    )
    expect_bad(f"A-{tag}-plain-unsign", lambda tsv=tsv: signer.unsign(tok(ts=tsv)))

expect_value("A-validate-returns-bool", lambda: signer.validate(tok(ts=HUGE), max_age=60), False)
expect_bad("A-serializer-loads", lambda: tser.loads(stok(tser, {"a": 1}, HUGE)), payload=b'{"a": 1}')
expect_bad(
    "A-serializer-loads-max_age",
    lambda: tser.loads(stok(tser, {"a": 1}, MS_CLOCK), max_age=3600),
    payload=b'{"a": 1}',
)
expect_bad(
    "A-serializer-loads-ret-ts",
    lambda: tser.loads(stok(tser, {"a": 1}, OVER_1), return_timestamp=True),
    payload=b'{"a": 1}',
)
expect_bad("A-urlsafe-loads", lambda: utser.loads(stok(utser, "a" * 400, HUGE)))

try:
    r = tser.loads_unsafe(stok(tser, {"a": 1}, HUGE))
    rows.append(("A-loads_unsafe-never-fails", isinstance(r, tuple) and len(r) == 2, repr(r)[:70]))
except BaseException as e:  # noqa: BLE001
    rows.append(("A-loads_unsafe-never-fails", False, f"RAW {type(e).__name__}: {str(e)[:50]}"))

class MillisSigner(TimestampSigner):
    def get_timestamp(self):
        return int(time.time() * 1000)


try:
    ms = MillisSigner(KEY)
    signed = ms.sign("value")
    out = ms.unsign(signed, return_timestamp=True)
    rows.append(("B-ms-clock-roundtrip", isinstance(out[1], datetime), repr(out)[:60]))
except BadData as e:
    rows.append(("B-ms-clock-roundtrip", True, f"BadData {type(e).__name__}"))
except BaseException as e:  # noqa: BLE001
    rows.append(("B-ms-clock-roundtrip", False, f"RAW {type(e).__name__}: {str(e)[:50]}"))

expect_value(
    "C-max-ok-return_timestamp",
    lambda: signer.unsign(tok(ts=MAX_OK), return_timestamp=True),
    (b"value", dt(MAX_OK)),
)
expect_expired_dated("C-max-ok-future-max_age", lambda: signer.unsign(tok(ts=MAX_OK), max_age=60), MAX_OK)
expect_value("C-max-ok-plain-unsign", lambda: signer.unsign(tok(ts=MAX_OK)), b"value")
expect_value("C-max-ok-validate", lambda: signer.validate(tok(ts=MAX_OK)), True)

future = int(time.time()) + 3600
past = int(time.time()) - 100
expect_expired_dated("D-future-signed-expired", lambda: signer.unsign(tok(ts=future), max_age=60), future)
expect_expired_dated("D-normal-expiry", lambda: signer.unsign(tok(ts=past), max_age=60), past)
expect_value("D-fresh-token", lambda: signer.unsign(tok(ts=int(time.time())), max_age=60), b"value")
expect_expired_dated("D-epoch-ts0", lambda: signer.unsign(tok(ts=0), max_age=60), 0)
expect_value("D-serializer-roundtrip", lambda: tser.loads(tser.dumps({"a": 1})), {"a": 1})
expect_value("D-urlsafe-roundtrip", lambda: utser.loads(utser.dumps("a" * 400)), "a" * 400)
got = None
try:
    got = tser.loads(tser.dumps({"a": 1}), return_timestamp=True)
    ok = (
        got[0] == {"a": 1}
        and isinstance(got[1], datetime)
        and got[1].tzinfo == timezone.utc
    )
except BaseException as e:  # noqa: BLE001
    ok = False
rows.append(("D-serializer-ret-ts-aware", ok, repr(got)[:60]))

expect_bad(
    "E-sigerr-unparseable-ts",
    lambda: signer.unsign(b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"),
    payload=b"value",
)
expect_bad("E-sigerr-out-of-range", lambda: signer.unsign(tok(ts=HUGE, key="other-key")), payload=b"value")
try:
    signer.unsign(b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY")
    err = None
except Exception as e:  # noqa: BLE001
    err = e
rows.append(
    ("E-sigerr-date_signed-None", err is not None and err.date_signed is None, f"date_signed={getattr(err, 'date_signed', '!')!r}")
)

try:
    from itsdangerous import MalformedTimestamp as MAL

    MAL_IMPORT = "ok"
except Exception as e:  # noqa: BLE001
    MAL = None
    MAL_IMPORT = f"{type(e).__name__}: {e}"


def expect_malformed(name, get, payload=ANY):
    """Signature valid + timestamp not representable: the raised object's class is
    MalformedTimestamp, it is not a SignatureExpired, it carries the payload and
    date_signed is None."""
    try:
        value = get()
    except BaseException as e:  # noqa: BLE001
        if MAL is None:
            rows.append(
                (name, False, f"raised {type(e).__name__}；顶层 MalformedTimestamp: {MAL_IMPORT}")
            )
            return
        ok = (
            isinstance(e, MAL)
            and not isinstance(e, SignatureExpired)
            and (payload is ANY or getattr(e, "payload", None) == payload)
            and getattr(e, "date_signed", "absent") is None
        )
        rows.append(
            (
                name,
                ok,
                f"{type(e).__name__} msg={str(e)[:26]!r}"
                f" payload={getattr(e, 'payload', None)!r}"
                f" date_signed={getattr(e, 'date_signed', '!')!r}",
            )
        )
        return
    rows.append((name, False, f"no error, value={value!r}"[:88]))


def expect_unchanged_bts(name, get, payload=ANY, message="Malformed timestamp"):
    """This route keeps its reading: BadTimeSignature with the same message and
    payload, and it is not a MalformedTimestamp."""
    try:
        value = get()
    except BaseException as e:  # noqa: BLE001
        checks = [
            type(e).__name__ == "BadTimeSignature",
            str(e) == message,
            payload is ANY or getattr(e, "payload", None) == payload,
        ]
        if MAL is not None:
            checks.append(not isinstance(e, MAL))
            read = ""
        else:
            read = " 顶层无 MalformedTimestamp 可比对"
        rows.append(
            (
                name,
                all(checks),
                f"{type(e).__name__} msg={str(e)[:26]!r}"
                f" payload={getattr(e, 'payload', None)!r} 判定={checks}{read}",
            )
        )
        return
    rows.append((name, False, f"no error, value={value!r}"[:88]))


rows.append(
    (
        "N-malformed-importable-from-itsdangerous",
        MAL is not None,
        f"from itsdangerous import MalformedTimestamp -> {MAL_IMPORT}",
    )
)

if MAL is None:
    rows.append(("N-malformed-class-shape", False, f"MalformedTimestamp: {MAL_IMPORT}"))
else:
    shape = (
        isinstance(MAL, type)
        and issubclass(MAL, BadTimeSignature)
        and MAL is not BadTimeSignature
        and not issubclass(MAL, SignatureExpired)
    )
    rows.append(
        (
            "N-malformed-class-shape",
            shape,
            f"mro={[c.__name__ for c in MAL.__mro__]}"[:88],
        )
    )

for tag, tsv in (("over1", OVER_1), ("ms", MS_CLOCK), ("huge", HUGE), ("i64", MAX_I64)):
    expect_malformed(
        f"N-{tag}-plain-unsign-exact-class",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv)),
    )
    expect_malformed(
        f"N-{tag}-return-ts-exact-class",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), return_timestamp=True),
    )
    expect_malformed(
        f"N-{tag}-max-age-exact-class",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), max_age=60),
    )
    expect_malformed(
        f"N-{tag}-neg-max-age-exact-class",
        lambda tsv=tsv: signer.unsign(tok(ts=tsv), max_age=-(2 ** 63)),
    )

expect_unchanged_bts(
    "N-sigerr-unrepresentable-keeps-plain-reading",
    lambda: signer.unsign(tok(ts=HUGE, key="other-key")),
    payload=b"value",
)

K1, K2, K_OTHER = "key-oldest", "key-newest", "key-not-in-the-list"
CREATED = []


class CountingSigner(TimestampSigner):
    """Counts how many times a fallback signer gets instantiated."""

    def __init__(self, *args, **kwargs):
        CREATED.append(1)
        super().__init__(*args, **kwargs)


def stok_signed_by(s, obj, ts, key):
    """Hand-built TimedSerializer-shaped token signed with one given key."""
    payload = s.dump_payload(obj)
    body = payload + b"." + base64_encode(int_to_bytes(ts))
    one = TimestampSigner(key, salt=s.salt)
    return body + b"." + one.get_signature(body)


ser2 = TimedSerializer([K1, K2], fallback_signers=[CountingSigner])
S1_TOKEN = stok_signed_by(ser2, {"a": 1}, HUGE, K2)
S2_TOKEN = stok_signed_by(ser2, {"a": 1}, HUGE, K_OTHER)

expect_malformed(
    "S1-serializer-loads-exact-class",
    lambda: ser2.loads(S1_TOKEN),
    payload=b'{"a": 1}',
)

CREATED.clear()
try:
    v = ser2.loads(S1_TOKEN)
    rows.append(("S1b-serializer-stops-at-first-signer", False, f"no error, value={v!r}"[:70]))
except BaseException as e:  # noqa: BLE001
    rows.append(
        (
            "S1b-serializer-stops-at-first-signer",
            not CREATED and isinstance(e, BadData),
            f"其后 signer 实例数={len(CREATED)} 抛出={type(e).__name__}",
        )
    )

CREATED.clear()
try:
    v = ser2.loads(S2_TOKEN)
    rows.append(("S2-serializer-tries-every-signer", False, f"no error, value={v!r}"[:70]))
except BaseException as e:  # noqa: BLE001
    rows.append(
        (
            "S2-serializer-tries-every-signer",
            len(CREATED) == 2 and isinstance(e, BadData),
            f"fallback signer 实例数={len(CREATED)}/2 抛出={type(e).__name__}",
        )
    )

expect_unchanged_bts(
    "S2b-serializer-wrong-sig-keeps-plain-reading",
    lambda: ser2.loads(S2_TOKEN),
    payload=b'{"a": 1}',
)

try:
    r = ser2.loads_unsafe(S1_TOKEN)
    rows.append(
        (
            "S3-loads_unsafe-malformed-token-never-raises",
            isinstance(r, tuple) and r[0] is False and r[1] == {"a": 1},
            repr(r)[:70],
        )
    )
except BaseException as e:  # noqa: BLE001
    rows.append(
        ("S3-loads_unsafe-malformed-token-never-raises", False, f"RAW {type(e).__name__}: {str(e)[:50]}")
    )

fails = 0
for name, ok, detail in rows:
    if ok:
        print(f"PASS\t{name}\t{detail}")
    else:
        fails += 1
        print(f"FAIL\t{name}\t{detail}")

print(f"TOTAL {len(rows)} rows, {fails} FAIL")
