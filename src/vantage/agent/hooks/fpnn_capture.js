/*
 * FPNN capture (OBSERVATION ONLY).
 * Captures raw FPNN TCP frames off the socket layer so the Python side can parse
 * framing + MessagePack. Also records connection lifecycle (connect/close) for
 * the connection map / heartbeat / reconnect analysis.
 *
 * It NEVER modifies, drops, delays, injects, or replays bytes. send()/recv() are
 * observed (arguments/return read) and the original call proceeds unchanged.
 *
 * Detection: a socket is tagged FPNN when the first bytes of its stream match the
 * FPNN magic ("FPNN"). Only tagged sockets are byte-captured; others contribute
 * connection/timeline metadata only (e.g. 443/TLS shows host+sizes, not plaintext).
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var F = (CFG.fpnn_capture || {});
  var P = 'P5';
  var MAGIC = [0x46, 0x50, 0x4e, 0x4e]; // "FPNN"
  var maxBytes = F.max_capture_bytes || (8 * 1024 * 1024);
  var captured = 0;
  var fds = new Map(); // fd -> {peer, fpnn:0/1/-1, txSeq, rxSeq, openedTs}

  function peerOf(fd) { return (S.socketFds && S.socketFds.get(fd)) || fds.get(fd) && fds.get(fd).peer || {}; }

  function isMagic(ptr_, n) {
    try { if (n < 4) return false; for (var i = 0; i < 4; i++) if (ptr_.add(i).readU8() !== MAGIC[i]) return false; return true; } catch (e) { return false; }
  }

  function st(fd) { if (!fds.has(fd)) fds.set(fd, { peer: {}, fpnn: 0, txSeq: 0, rxSeq: 0, openedTs: Date.now() }); return fds.get(fd); }

  function parseSockaddr(sa) {
    try {
      if (!sa || sa.isNull()) return null;
      var fam = sa.readU16();
      if (fam === 2) return { family: 'IPv4', ip: [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.'), port: (sa.add(2).readU8() << 8) | sa.add(3).readU8() };
      if (fam === 10) { var parts = []; for (var i = 0; i < 16; i += 2) parts.push((((sa.add(8 + i).readU8()) << 8) | sa.add(8 + i + 1).readU8()).toString(16)); return { family: 'IPv6', ip: parts.join(':'), port: (sa.add(2).readU8() << 8) | sa.add(3).readU8() }; }
      return { family: 'AF_' + fam };
    } catch (e) { return null; }
  }

  function emitChunk(fd, dir, buf, n) {
    if (captured >= maxBytes) return;
    var take = Math.min(n, maxBytes - captured);
    var s = st(fd);
    var seq = dir === 'tx' ? s.txSeq++ : s.rxSeq++;
    var ba = null;
    try { ba = buf.readByteArray(take); } catch (e) { return; }
    captured += take;
    KS.log.bytes(P, 'fpnn_chunk', { fd: fd, dir: dir, seq: seq, len: take, ts: KS.log.now(), peer: peerOf(fd) }, ba);
  }

  function hookConnect() {
    var p = U.exp(null, 'connect'); if (!p) return;
    U.attachSafe('P5:connect', p, {
      onEnter: function (args) { this.fd = args[0].toInt32(); this.peer = parseSockaddr(args[1]); },
      onLeave: function () {
        if (!this.peer || this.peer.family === 'AF_UNIX') return;
        var s = st(this.fd); s.peer = this.peer; s.openedTs = Date.now();
        if (S.socketFds) S.socketFds.set(this.fd, this.peer);
        KS.log.important(P, 'conn_open', { fd: this.fd, peer: this.peer, ts: KS.log.now() });
      }
    });
  }

  function hookClose() {
    var p = U.exp(null, 'close'); if (!p) return;
    U.attachSafe('P5:close', p, {
      onEnter: function (args) { this.fd = args[0].toInt32(); this.known = fds.has(this.fd) && fds.get(this.fd).fpnn === 1; },
      onLeave: function () {
        if (!this.known) return;
        var s = fds.get(this.fd);
        KS.log.important(P, 'conn_close', { fd: this.fd, peer: s.peer, lifetime_ms: Date.now() - s.openedTs, tx_chunks: s.txSeq, rx_chunks: s.rxSeq });
      }
    });
  }

  function tag(fd, buf, n, dir) {
    var s = st(fd);
    if (s.fpnn === 0) {
      if (isMagic(buf, n)) { s.fpnn = 1; KS.log.important(P, 'fpnn_detected', { fd: fd, dir: dir, peer: s.peer }); }
      else if ((s.txSeq + s.rxSeq) > 3) { s.fpnn = -1; } // not FPNN after a few chunks
    }
    return s.fpnn === 1;
  }

  function hookSend() {
    [['send', 1, 2], ['write', 1, 2], ['sendto', 1, 2]].forEach(function (t) {
      var p = U.exp(null, t[0]); if (!p) return;
      U.attachSafe('P5:' + t[0], p, {
        onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[t[1]]; this.len = args[t[2]].toInt32(); this.sock = fds.has(this.fd) || (S.socketFds && S.socketFds.has(this.fd)); },
        onLeave: function (ret) {
          if (!this.sock) return; var n = ret.toInt32(); if (n <= 0) return;
          if (tag(this.fd, this.buf, n, 'tx')) emitChunk(this.fd, 'tx', this.buf, n);
        }
      });
    });
  }

  function hookRecv() {
    [['recv', 1], ['read', 1], ['recvfrom', 1]].forEach(function (t) {
      var p = U.exp(null, t[0]); if (!p) return;
      U.attachSafe('P5:' + t[0], p, {
        onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[t[1]]; this.sock = fds.has(this.fd) || (S.socketFds && S.socketFds.has(this.fd)); },
        onLeave: function (ret) {
          if (!this.sock) return; var n = ret.toInt32(); if (n <= 0) return;
          if (tag(this.fd, this.buf, n, 'rx')) emitChunk(this.fd, 'rx', this.buf, n);
        }
      });
    });
  }

  KS.phase5 = {
    init: function () {
      hookConnect(); hookClose(); hookSend(); hookRecv();
      KS.log.important(P, 'phase_ready', { max_capture_bytes: maxBytes, note: 'observation only — raw FPNN frames streamed to host for offline parsing' });
    }
  };
})();
