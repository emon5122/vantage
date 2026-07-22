/*
 * core/logger.js — structured, timestamped, throttled event emitter.
 * OBSERVATION ONLY. Never mutates process state.
 *
 * Every event is shipped to the Python host via send({__ks:1,...}) and the
 * host writes it to newline-delimited JSON (events.jsonl). Bulk byte dumps go
 * out as the message's binary payload to avoid bloating the JSON line.
 */
(function () {
  var CFG = (globalThis.KS_CONFIG || {});
  var LIM = (CFG.limits || {});
  var maxPerSec = LIM.max_events_per_sec || 400;

  var t0_wall = Date.now();
  // Monotonic clock if available (Frida >= 16 exposes performance.now in some runtimes)
  var hasPerf = (typeof performance !== 'undefined' && typeof performance.now === 'function');
  var t0_mono = hasPerf ? performance.now() : 0;

  var bucketSec = Math.floor(Date.now() / 1000);
  var bucketCount = 0;
  var dropped = 0;

  function nowStamp() {
    var w = Date.now();
    return {
      wall_ms: w,
      iso: new Date(w).toISOString(),
      rel_ms: w - t0_wall,
      mono_ms: hasPerf ? Math.round((performance.now() - t0_mono) * 1000) / 1000 : null
    };
  }

  function threadInfo() {
    try {
      return { tid: Process.getCurrentThreadId() };
    } catch (e) { return { tid: -1 }; }
  }

  function throttled() {
    var s = Math.floor(Date.now() / 1000);
    if (s !== bucketSec) {
      if (dropped > 0) {
        // flush a drop notice for this previous second
        try { send({ __ks: 1, ts: nowStamp(), phase: 'CORE', event: 'events_dropped', data: { count: dropped, sec: bucketSec } }); } catch (e) {}
      }
      bucketSec = s; bucketCount = 0; dropped = 0;
    }
    bucketCount++;
    if (bucketCount > maxPerSec) { dropped++; return true; }
    return false;
  }

  function emit(phase, event, data, opts) {
    opts = opts || {};
    if (!opts.important && throttled()) return;
    var msg = {
      __ks: 1,
      ts: nowStamp(),
      thread: threadInfo(),
      phase: phase,
      event: event,
      data: data || {}
    };
    try {
      if (opts.bytes) {
        // ship raw bytes as binary payload (host base64-encodes into the record)
        send(msg, opts.bytes);
      } else {
        send(msg);
      }
    } catch (e) { /* channel closed / detached */ }
  }

  globalThis.KS = globalThis.KS || {};
  KS.log = {
    now: nowStamp,
    event: function (phase, event, data, opts) { emit(phase, event, data, opts); },
    important: function (phase, event, data, opts) {
      opts = opts || {}; opts.important = true; emit(phase, event, data, opts);
    },
    error: function (phase, event, data) {
      emit(phase, event, Object.assign({ level: 'error' }, data || {}), { important: true });
    },
    bytes: function (phase, event, data, byteArray) {
      emit(phase, event, data, { bytes: byteArray, important: true });
    }
  };
})();
