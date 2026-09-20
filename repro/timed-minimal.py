"""签名有效但时间戳不可表示的 token，三个入口各是什么下场。
跑法：PYTHONPATH=src .venv/bin/python repro/timed-minimal.py
"""


import time
from datetime import datetime, timezone

from itsdangerous import TimestampSigner, TimedSerializer, URLSafeTimedSerializer
from itsdangerous.encoding import base64_encode, int_to_bytes


class AppSigner(TimestampSigner):
    """Producer whose clock hands out milliseconds (JS Date.now() interop)."""

    def get_timestamp(self):
        return int(time.time() * 1000)


print("python", time.time())

s = AppSigner("k")
signed = s.sign("user:42")
print("sign() ok ->", signed)
try:
    print("unsign ->", s.unsign(signed, return_timestamp=True))
except BaseException as e:
    print("unsign RAISED", type(e).__name__, e)

ser = TimedSerializer("k")
payload = ser.dump_payload({"user": 42})
body = payload + b"." + base64_encode(int_to_bytes(2 ** 62))
token = body + b"." + ser.make_signer().get_signature(body)
try:
    print("loads ->", ser.loads(token))
except BaseException as e:
    print("loads RAISED", type(e).__name__, e)

try:
    print("loads_unsafe ->", ser.loads_unsafe(token))
except BaseException as e:
    print("loads_unsafe RAISED", type(e).__name__, e)

try:
    print("signer validate ->", AppSigner("k").validate(signed, max_age=60))
except BaseException as e:
    print("signer validate RAISED", type(e).__name__, e)

try:
    print("TimestampSigner validate(huge token) ->", TimestampSigner("k").validate(token, max_age=60))
except BaseException as e:
    print("TimestampSigner validate RAISED", type(e).__name__, e)

ok = 253_402_300_799
body2 = b"value" + b"." + base64_encode(int_to_bytes(ok))
t2 = body2 + b"." + TimestampSigner("k").get_signature(body2)
print("max representable ->", TimestampSigner("k").unsign(t2, return_timestamp=True))
print("cutoff year is 9999 ->", datetime.fromtimestamp(ok, tz=timezone.utc).year == 9999)
