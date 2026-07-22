/*
 * core/state.js — cross-phase shared state + a tiny in-agent event bus.
 * Lets Phase C tell Phase D "watch this buffer", Phase E feed Phase F, etc.
 */
(function () {
  globalThis.KS = globalThis.KS || {};

  KS.state = {
    modules: [],            // [{name, base, seq, ts}]
    moduleSeq: 0,
    socketFds: new Map(),   // fd -> {ip, port, family, label}
    interestFds: new Set(), // fds that opened a metadata/bundle file
    metadataRegions: [],    // [{base, size, tag}]
    il2cpp: {},             // resolved il2cpp NativeFunctions/pointers
    lua: {},                // resolved lua pointers
    counters: {}
  };

  var subs = {};
  KS.bus = {
    on: function (topic, cb) { (subs[topic] = subs[topic] || []).push(cb); },
    emit: function (topic, data) {
      var l = subs[topic] || [];
      for (var i = 0; i < l.length; i++) { try { l[i](data); } catch (e) { KS.log.error('BUS', 'handler', { topic: topic, err: String(e) }); } }
    }
  };

  KS.count = function (k) {
    KS.state.counters[k] = (KS.state.counters[k] || 0) + 1;
    return KS.state.counters[k];
  };
})();
