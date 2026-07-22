"""Unit tests for the dependency-free MessagePack decoder."""
import struct

import pytest

from vantage.protocol.msgpack import decode, MsgpackError, to_jsonable
from vantage.protocol.synthetic import mp


@pytest.mark.parametrize("value", [
    0, 1, 127, -1, -32, 255, 65535, 4294967295, -128, 2**40, -(2**40),
    True, False, None, 1.5, -0.25,
    "", "hello", "x" * 40,
    [1, 2, 3], [], ["a", ["b", 2]],
    {1: "a", 2: 2, 3: [1, 2]}, {}, {"k": {"nested": True}},
])
def test_roundtrip(value):
    val, tnode, consumed = decode(mp(value))
    assert consumed == len(mp(value))
    # int keys survive; compare via jsonable normalisation for maps
    if isinstance(value, dict):
        assert to_jsonable(val) == to_jsonable(value)
    else:
        assert val == value


def test_type_annotations():
    _, tnode, _ = decode(mp({1: "a", 2: [1, 2]}))
    assert tnode["t"] == "map"
    fields = tnode["fields"]
    key = 1 if 1 in fields else "1"
    assert fields[key]["t"] == "str"


def test_truncated_raises():
    with pytest.raises(MsgpackError):
        decode(b"\xce\x00\x00")  # uint32 header, missing bytes


def test_bin_and_ext_are_jsonsafe():
    # bin8 of 2 bytes
    val, _, _ = decode(b"\xc4\x02\xab\xcd")
    assert val == {"$bin": "abcd", "len": 2}
    # fixext1 code=5
    val, _, _ = decode(b"\xd4\x05\x99")
    assert val["$ext"] == 5


def test_float64_exact():
    val, tnode, _ = decode(b"\xcb" + struct.pack(">d", 3.140625))
    assert val == 3.140625 and tnode["t"] == "float64"
