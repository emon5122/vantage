/*
 * Request mapping & (heuristic) classification.
 * Aggregates Phase E events into per-connection request records and emits a
 * periodic summary. Classification is HEURISTIC (payloads are encrypted /
 * MessagePack-framed); every classified label is marked confidence:"heuristic".
 *
 * Signals used (no packet modification, no decryption):
 *   - destination port/label (443 -> HTTP API; fpnn port -> game gateway)
 *   - temporal pattern (first burst after connect -> login; small periodic -> heartbeat)
 *   - payload size buckets
 *   - correlated il2cpp/icall/lua hints when available (Phases B/H/I)
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var P = 'F';

  var conns = new Map(); // fd -> {peer, opened, txCount, rxCount, txBytes, rxBytes, firstTxTs, lastTxTs, gaps:[]}
  var CATEGORIES = ['Login', 'Heartbeat', 'Building', 'March', 'Research', 'Alliance', 'Mail', 'Chat', 'Store', 'Purchases', 'Unknown'];

  function conn(fd, peer) {
    if (!conns.has(fd)) conns.set(fd, { peer: peer || {}, opened: Date.now(), txCount: 0, rxCount: 0, txBytes: 0, rxBytes: 0, firstTxTs: null, lastTxTs: null, sizes: [], gaps: [] });
    return conns.get(fd);
  }

  function classify(c, len) {
    // Returns {label, confidence, why}
    var port = c.peer.port;
    var lbl = c.peer.label || 'tcp';
    var now = Date.now();
    var sinceOpen = now - c.opened;

    // HTTP(S) API port -> version/login/store/purchase family
    if (port === 443 || port === 80 || lbl.indexOf('http') === 0) {
      if (c.txCount <= 2) return { label: 'Login', confidence: 'heuristic', why: 'first HTTPS request post-connect (version/login bootstrap)' };
      if (len < 256) return { label: 'Heartbeat', confidence: 'heuristic', why: 'small periodic HTTPS' };
      return { label: 'Store', confidence: 'heuristic', why: 'HTTPS API request (store/purchase/config family)' };
    }
    // FPNN raw TCP game gateway
    if (lbl.indexOf('fpnn') === 0 || (port >= 13000 && port <= 13099)) {
      if (c.txCount === 1) return { label: 'Login', confidence: 'heuristic', why: 'first FPNN Quest after gateway connect' };
      // periodic small packets ~ heartbeat
      var gap = c.lastTxTs ? (now - c.lastTxTs) : null;
      if (len < 96 && gap && gap > 8000) return { label: 'Heartbeat', confidence: 'heuristic', why: 'small FPNN packet on long interval' };
      if (len > 400) return { label: 'March', confidence: 'heuristic', why: 'larger FPNN Quest (action/march/battle family)' };
      return { label: 'Building', confidence: 'heuristic', why: 'medium FPNN Quest (building/research/alliance family)' };
    }
    return { label: 'Unknown', confidence: 'heuristic', why: 'unclassified transport' };
  }

  function onTx(d) {
    var c = conn(d.fd, d.peer);
    var now = Date.now();
    if (c.lastTxTs) c.gaps.push(now - c.lastTxTs);
    c.txCount++; c.txBytes += d.len; c.sizes.push(d.len);
    if (!c.firstTxTs) c.firstTxTs = now; c.lastTxTs = now;

    var cls = classify(c, d.len);
    var rec = {
      ts: KS.log.now(),
      thread: { tid: Process.getCurrentThreadId() },
      dest: (d.peer.ip || '?') + ':' + (d.peer.port || '?'),
      transport: d.peer.label || 'tcp',
      payload_len: d.len,
      seq_on_conn: c.txCount,
      classification: cls,
      bt: U.backtrace(d.ctx, 'network_send')
    };
    KS.log.important(P, 'request', rec);
    KS.count('req_' + cls.label);
  }

  function onRx(d) {
    var c = conn(d.fd, d.peer);
    c.rxCount++; c.rxBytes += d.len;
  }

  function summary() {
    var arr = [];
    conns.forEach(function (c, fd) {
      arr.push({ fd: fd, dest: (c.peer.ip || '?') + ':' + (c.peer.port || '?'), label: c.peer.label,
        tx: { count: c.txCount, bytes: c.txBytes }, rx: { count: c.rxCount, bytes: c.rxBytes },
        avg_tx: c.txCount ? Math.round(c.txBytes / c.txCount) : 0,
        median_gap_ms: median(c.gaps) });
    });
    var byCat = {};
    CATEGORIES.forEach(function (k) { if (S.counters['req_' + k]) byCat[k] = S.counters['req_' + k]; });
    KS.log.important(P, 'summary', { connections: arr, by_category: byCat });
  }

  function median(a) { if (!a.length) return null; var s = a.slice().sort(function (x, y) { return x - y; }); return s[Math.floor(s.length / 2)]; }

  KS.phaseF = {
    init: function () {
      KS.bus.on('connect', function (r) { conn(r.fd, r); });
      KS.bus.on('tx', onTx);
      KS.bus.on('rx', onRx);
      setInterval(summary, 15000);
      KS.log.important(P, 'phase_ready', { categories: CATEGORIES, note: 'classification is heuristic; payloads are not decrypted' });
    }
  };
})();
