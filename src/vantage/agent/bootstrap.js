/*
 * index.js — bootstrap. Runs LAST (the launcher concatenates core + phases,
 * then this file). Initializes enabled phases in dependency order and exposes
 * a small rpc surface for the Python host.
 *
 * OBSERVATION-ONLY toolkit. No memory patching, no security bypass, no packet
 * modification. See README.md "Scope & Safety".
 */
(function () {
  var CFG = (globalThis.KS_CONFIG || {});
  var ph = CFG.phases || {};
  var P = 'BOOT';

  KS.log.important(P, 'agent_start', {
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    pointerSize: Process.pointerSize,
    frida: (typeof Frida !== 'undefined' ? Frida.version : 'unknown'),
    package: CFG.package,
    phases_enabled: Object.keys(ph).filter(function (k) { return ph[k]; })
  });

  // Phase order matters: A installs loader hooks; B resolves il2cpp used by G/H.
  var ORDER = [
    ['A_process', 'phaseA'],
    ['B_il2cpp', 'phaseB'],
    ['C_metadata', 'phaseC'],
    ['D_decrypt', 'phaseD'],
    ['E_network', 'phaseE'],
    ['F_requests', 'phaseF'],
    ['G_assets', 'phaseG'],
    ['H_strings', 'phaseH'],
    ['I_lua', 'phaseI']
  ];

  ORDER.forEach(function (pair) {
    var key = pair[0], obj = pair[1];
    if (ph[key] === false) { KS.log.event(P, 'phase_disabled', { phase: key }); return; }
    try {
      if (KS[obj] && typeof KS[obj].init === 'function') KS[obj].init();
      else KS.log.error(P, 'phase_missing', { phase: key, obj: obj });
    } catch (e) {
      KS.log.error(P, 'phase_init_fail', { phase: key, err: String(e), stack: e.stack });
    }
  });

  KS.log.important(P, 'agent_ready', { note: 'observation active' });

  rpc.exports = {
    modules: function () { return KS.state.modules; },
    counters: function () { return KS.state.counters; },
    summary: function () {
      return {
        modules: KS.state.modules.length,
        sockets: KS.state.socketFds.size,
        metadataRegions: KS.state.metadataRegions.length,
        il2cpp: Object.keys((KS.state.il2cpp.ptrs || {})),
        counters: KS.state.counters
      };
    },
    ping: function () { return 'pong'; }
  };
})();
