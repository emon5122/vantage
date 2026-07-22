/*
 * phase4_metadata.js — orchestrator for IL2CPP runtime metadata recovery.
 * Sequence: locate API -> (optional) regscan -> traverse -> classify+correlate
 * each class -> stream results. Everything is read-only.
 *
 * rpc: KS.phase4.recover({names_only, max_classes, method_cap}) can be driven
 * from the host (recover.py) after init, so recovery starts only when the
 * managed domain is up (avoid racing il2cpp_init).
 */
(function () {
  var S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var RC = (CFG.il2cpp_recovery || {});
  var P = 'B4';
  var started = false;

  function classifyStream() {
    KS.bus.on('managed_class', function (rec) {
      try {
        var sc = KS.il2cppClassify.scoreOne(rec.assembly, rec.ns, rec.name);
        if (!sc.role) return; // only emit classified (networking/serialization/etc.) classes
        var corr = KS.il2cppCorrelate ? KS.il2cppCorrelate.correlate(rec, rec) : { extra: 0, evidence: [] };
        var conf = Math.min(1, sc.confidence + corr.extra);
        KS.log.important(P, 'recovered_class', {
          assembly: rec.assembly, ns: rec.ns, name: rec.name,
          role: sc.role, confidence: Math.round(conf * 100) / 100,
          tier: conf >= 0.75 ? 'high' : (conf >= 0.5 ? 'medium' : 'low'),
          categories: sc.categories, reasons: sc.reasons, correlation: corr.evidence,
          verified: 'runtime_metadata',
          method_count: rec.method_count,
          methods: (rec.methods || []).map(function (m) {
            return { name: m.name, params: m.param_count, ret: m.return_type, param_types: m.params, rva: m.rva ? m.rva.rva : null };
          })
        });
      } catch (e) { KS.log.error(P, 'classify_stream', { err: String(e) }); }
    });
  }

  function locateAndRecover(opts) {
    if (started && !opts.force) { KS.log.event(P, 'already_started', {}); return { ok: !!S.il2cpp.fns }; }
    started = true;
    if (KS.il2cppCorrelate) KS.il2cppCorrelate.init();
    classifyStream();

    var located = KS.il2cppLocator.locate();
    if (RC.regscan !== false) { try { KS.il2cppRegScan.run(); } catch (e) { KS.log.error(P, 'regscan', { err: String(e) }); } }

    if (!located) {
      KS.log.important(P, 'recovery_blocked', { reason: 'IL2CPP API not located — see api_locator remedy. regscan candidates (if any) were reported for offset bootstrapping.' });
      return { ok: false };
    }
    KS.il2cppTraverse.run({ names_only: !!opts.names_only, max_classes: opts.max_classes, method_cap: opts.method_cap });
    KS.log.important(P, 'recovery_complete', { stats: S.il2cpp.stats, locator: S.il2cpp.locator });
    return { ok: true, stats: S.il2cpp.stats };
  }

  KS.phase4 = {
    init: function () {
      KS.log.important(P, 'phase4_ready', {
        note: 'call rpc recover() from host after the game reaches its managed domain',
        allow_behavioral_probe: !!RC.allow_behavioral_probe
      });
    },
    recover: function (opts) { return locateAndRecover(opts || {}); }
  };
})();
