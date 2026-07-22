"""
msgpack_decode.py — dependency-free MessagePack decoder (observation/decoding only).

Decodes captured payload bytes into Python objects and a parallel TYPE tree used
for schema inference. It only READS bytes; it never encodes/injects/modifies.

Reference: MessagePack spec (github.com/msgpack/msgpack/blob/master/spec.md).
Handles: nil, bool, int (fix/8/16/32/64 signed+unsigned), float32/64,
str (fix/8/16/32), bin (8/16/32), array (fix/16/32), map (fix/16/32), ext,
and the timestamp extension (-1).

Map keys may be ints (common in compact game protocols → "field numbers") — these
are preserved. bin/ext are wrapped so the result is JSON-serialisable.
"""
import struct


class MsgpackError(Exception):
    pass


class Decoder:
    def __init__(self, buf, offset=0):
        self.b = buf
        self.o = offset
        self.n = len(buf)

    def _need(self, k):
        if self.o + k > self.n:
            raise MsgpackError(f"truncated: need {k} at {self.o}/{self.n}")

    def _u8(self):
        self._need(1); v = self.b[self.o]; self.o += 1; return v

    def _read(self, k):
        self._need(k); v = self.b[self.o:self.o + k]; self.o += k; return v

    def decode(self):
        """Return (value, type_node). type_node describes types for schema inference."""
        c = self._u8()
        # positive fixint
        if c <= 0x7f:
            return c, {"t": "int", "v": c}
        # negative fixint
        if c >= 0xe0:
            return c - 0x100, {"t": "int", "v": c - 0x100}
        # fixmap
        if 0x80 <= c <= 0x8f:
            return self._map(c & 0x0f)
        # fixarray
        if 0x90 <= c <= 0x9f:
            return self._array(c & 0x0f)
        # fixstr
        if 0xa0 <= c <= 0xbf:
            return self._str(c & 0x1f)
        if c == 0xc0:
            return None, {"t": "nil"}
        if c == 0xc2:
            return False, {"t": "bool"}
        if c == 0xc3:
            return True, {"t": "bool"}
        if c == 0xc4:
            return self._bin(self._u8())
        if c == 0xc5:
            return self._bin(struct.unpack(">H", self._read(2))[0])
        if c == 0xc6:
            return self._bin(struct.unpack(">I", self._read(4))[0])
        if c == 0xc7:
            ln = self._u8(); return self._ext(ln)
        if c == 0xc8:
            ln = struct.unpack(">H", self._read(2))[0]; return self._ext(ln)
        if c == 0xc9:
            ln = struct.unpack(">I", self._read(4))[0]; return self._ext(ln)
        if c == 0xca:
            v = struct.unpack(">f", self._read(4))[0]; return v, {"t": "float32"}
        if c == 0xcb:
            v = struct.unpack(">d", self._read(8))[0]; return v, {"t": "float64"}
        if c == 0xcc:
            v = self._u8(); return v, {"t": "uint8", "v": v}
        if c == 0xcd:
            v = struct.unpack(">H", self._read(2))[0]; return v, {"t": "uint16", "v": v}
        if c == 0xce:
            v = struct.unpack(">I", self._read(4))[0]; return v, {"t": "uint32", "v": v}
        if c == 0xcf:
            v = struct.unpack(">Q", self._read(8))[0]; return v, {"t": "uint64", "v": v}
        if c == 0xd0:
            v = struct.unpack(">b", self._read(1))[0]; return v, {"t": "int8", "v": v}
        if c == 0xd1:
            v = struct.unpack(">h", self._read(2))[0]; return v, {"t": "int16", "v": v}
        if c == 0xd2:
            v = struct.unpack(">i", self._read(4))[0]; return v, {"t": "int32", "v": v}
        if c == 0xd3:
            v = struct.unpack(">q", self._read(8))[0]; return v, {"t": "int64", "v": v}
        if c == 0xd9:
            return self._str(self._u8())
        if c == 0xda:
            return self._str(struct.unpack(">H", self._read(2))[0])
        if c == 0xdb:
            return self._str(struct.unpack(">I", self._read(4))[0])
        if c == 0xdc:
            return self._array(struct.unpack(">H", self._read(2))[0])
        if c == 0xdd:
            return self._array(struct.unpack(">I", self._read(4))[0])
        if c == 0xde:
            return self._map(struct.unpack(">H", self._read(2))[0])
        if c == 0xdf:
            return self._map(struct.unpack(">I", self._read(4))[0])
        if c in (0xd4, 0xd5, 0xd6, 0xd7, 0xd8):  # fixext 1/2/4/8/16
            ln = {0xd4: 1, 0xd5: 2, 0xd6: 4, 0xd7: 8, 0xd8: 16}[c]
            return self._ext(ln)
        raise MsgpackError(f"unknown msgpack byte 0x{c:02x} at {self.o - 1}")

    def _str(self, ln):
        raw = self._read(ln)
        try:
            s = raw.decode("utf-8")
            return s, {"t": "str", "len": ln}
        except UnicodeDecodeError:
            return {"$str_raw": raw.hex()}, {"t": "str?", "len": ln}

    def _bin(self, ln):
        raw = self._read(ln)
        return {"$bin": raw.hex(), "len": ln}, {"t": "bin", "len": ln}

    def _ext(self, ln):
        code = struct.unpack(">b", self._read(1))[0]
        raw = self._read(ln)
        if code == -1:  # timestamp extension
            return {"$timestamp_ext": raw.hex()}, {"t": "timestamp"}
        return {"$ext": code, "data": raw.hex()}, {"t": "ext", "code": code}

    def _array(self, cnt):
        vals, types = [], []
        for _ in range(cnt):
            v, tn = self.decode(); vals.append(v); types.append(tn)
        return vals, {"t": "array", "len": cnt, "items": types}

    def _map(self, cnt):
        d = {}
        fields = {}
        for _ in range(cnt):
            k, kt = self.decode()
            v, vt = self.decode()
            key = k if isinstance(k, (int, str)) else str(k)
            d[key] = v
            fields[key] = vt
        return d, {"t": "map", "len": cnt, "fields": fields}


def decode(buf, offset=0):
    """Decode one msgpack object. Returns (value, type_node, bytes_consumed)."""
    dec = Decoder(buf, offset)
    val, tnode = dec.decode()
    return val, tnode, dec.o - offset


def to_jsonable(obj):
    """Convert decoded object (may have int map keys) to a JSON-safe structure."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kk = f"#{k}" if isinstance(k, int) else k
            out[kk] = to_jsonable(v)
        return out
    if isinstance(obj, list):
        return [to_jsonable(x) for x in obj]
    return obj


if __name__ == "__main__":
    # tiny smoke test: fixmap {1: "login", 2: [1,2,3]}
    sample = bytes([0x82, 0x01, 0xa5]) + b"login" + bytes([0x02, 0x93, 0x01, 0x02, 0x03])
    v, t, n = decode(sample)
    print("decoded:", v, "consumed:", n)
