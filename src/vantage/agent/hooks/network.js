/*
 * Network OBSERVATION (never alters traffic).
 * connect(), send/sendto/write, recv/recvfrom/read, getaddrinfo (DNS),
 * and SSL_read/SSL_write if a native TLS lib is present.
 *
 * Target notes:
 *   - FPNN game/RTM traffic is raw TCP -> send/recv see the (MessagePack)
 *     framing directly (possibly with the app's own layer on top).
 *   - BestHTTP uses MANAGED BouncyCastle TLS, so native SSL_* hooks will NOT
 *     see its plaintext; native send/recv see ciphertext + host:port only.
 * We log sizes + peer + (optional) small hex previews. No modification.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var N = CFG.network || {};
  var P = 'E';
  var dumpBytes = N.dump_bytes || 0;
  var dumpCapPerFd = N.dump_direction_max_per_fd || 4;
  var portLabels = N.port_labels || {};
  var fpnnPorts = new Set(N.fpnn_hint_ports || []);
  var dumpCounts = new Map();

  function parseSockaddr(sa) {
    try {
      if (!sa || sa.isNull()) return null;
      var family = sa.readU16();
      if (family === 2) { // AF_INET
        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        var ip = [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.');
        return { family: 'IPv4', ip: ip, port: port };
      } else if (family === 10) { // AF_INET6
        var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        var parts = [];
        for (var i = 0; i < 16; i += 2) parts.push((((sa.add(8 + i).readU8()) << 8) | sa.add(8 + i + 1).readU8()).toString(16));
        return { family: 'IPv6', ip: parts.join(':'), port: port6 };
      } else if (family === 1) {
        return { family: 'AF_UNIX', path: U.readCStr(sa.add(2), 108) };
      }
      return { family: 'AF_' + family };
    } catch (e) { return null; }
  }

  function label(port) {
    if (portLabels[String(port)]) return portLabels[String(port)];
    if (fpnnPorts.has(port)) return 'fpnn-tcp?';
    return 'tcp';
  }

  function hookConnect() {
    var p = U.exp(null, 'connect');
    if (!p) return;
    U.attachSafe('connect', p, {
      onEnter: function (args) { this.fd = args[0].toInt32(); this.peer = parseSockaddr(args[1]); },
      onLeave: function (ret) {
        if (!this.peer || this.peer.family === 'AF_UNIX') return;
        var lbl = label(this.peer.port);
        var rec = { fd: this.fd, ip: this.peer.ip, port: this.peer.port, family: this.peer.family, label: lbl };
        S.socketFds.set(this.fd, rec);
        KS.log.important(P, 'connect', Object.assign({ ret: ret.toInt32(), bt: U.backtrace(this.context, 'network_connect') }, rec));
        KS.bus.emit('connect', rec);
      }
    });
  }

  function hookDns() {
    if (N.resolve_dns === false) return;
    ['getaddrinfo', 'android_getaddrinfofornet'].forEach(function (fn) {
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.host = U.readCStr(args[0], 256); this.svc = U.readCStr(args[1], 64); },
        onLeave: function () {
          if (this.host) { KS.log.important(P, 'dns_lookup', { host: this.host, service: this.svc }); KS.bus.emit('dns', { host: this.host }); }
        }
      });
    });
  }

  function maybeDump(fd, dir, buf, n) {
    if (dumpBytes <= 0 || n <= 0) return null;
    var key = fd + ':' + dir;
    var c = dumpCounts.get(key) || 0;
    if (c >= dumpCapPerFd) return null;
    dumpCounts.set(key, c + 1);
    return U.hexPreview(buf, Math.min(n, dumpBytes));
  }

  function hookSend() {
    [['send', 1, 2], ['sendto', 1, 2], ['write', 1, 2]].forEach(function (t) {
      var fn = t[0], bufIdx = t[1], lenIdx = t[2];
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[bufIdx]; this.len = args[lenIdx].toInt32(); this.isSock = S.socketFds.has(this.fd); },
        onLeave: function (ret) {
          if (!this.isSock) return; // 'write' is also files — only sockets
          var n = ret.toInt32(); if (n <= 0) return;
          var peer = S.socketFds.get(this.fd) || {};
          var ev = { fn: fn, fd: this.fd, len: n, peer: peer, preview: maybeDump(this.fd, 'tx', this.buf, n), bt: U.backtrace(this.context, 'network_send') };
          KS.log.event(P, 'send', ev, { important: fn !== 'write' });
          KS.bus.emit('tx', { fd: this.fd, len: n, peer: peer, ctx: this.context });
        }
      });
    });
  }

  function hookRecv() {
    [['recv', 1], ['recvfrom', 1], ['read', 1]].forEach(function (t) {
      var fn = t[0], bufIdx = t[1];
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[bufIdx]; this.isSock = S.socketFds.has(this.fd); },
        onLeave: function (ret) {
          if (!this.isSock) return;
          var n = ret.toInt32(); if (n <= 0) return;
          var peer = S.socketFds.get(this.fd) || {};
          KS.log.event(P, 'recv', { fn: fn, fd: this.fd, len: n, peer: peer, preview: maybeDump(this.fd, 'rx', this.buf, n) }, { important: fn !== 'read' });
          KS.bus.emit('rx', { fd: this.fd, len: n, peer: peer });
        }
      });
    });
  }

  function hookSSL() {
    // Only fires if a NATIVE TLS lib exports these (e.g. conscrypt/boringssl in
    // an SDK). BestHTTP's managed BouncyCastle TLS will NOT appear here.
    var found = [];
    ['SSL_write', 'SSL_read'].forEach(function (fn) {
      var p = U.exp(null, fn);
      if (!p) return;
      found.push(fn);
      var dir = fn === 'SSL_write' ? 'tx' : 'rx';
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.ssl = args[0]; this.buf = args[1]; this.num = args[2].toInt32(); },
        onLeave: function (ret) {
          var n = ret.toInt32(); if (n <= 0) return;
          KS.log.event(P, 'ssl', { fn: fn, dir: dir, len: n, preview: U.hexPreview(this.buf, Math.min(n, dumpBytes || 32)) }, { important: true });
        }
      });
    });
    KS.log.important(P, 'ssl_symbols', { found: found, note: found.length ? 'native TLS present' : 'no native SSL_* exports (BestHTTP TLS is managed BouncyCastle — plaintext only visible via managed hooks)' });
  }

  KS.phaseE = {
    init: function () {
      hookConnect(); hookDns(); hookSend(); hookRecv(); hookSSL();
      KS.log.important(P, 'phase_ready', { dump_bytes: dumpBytes });
    }
  };
})();
