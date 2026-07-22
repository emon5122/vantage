/*
 * IL2CPP discovery.
 *
 * IMPORTANT: On this target libil2cpp.so has ENCRYPTED export names (HTProtect),
 * so the standard il2cpp_* symbols DO NOT resolve by name. This module therefore:
 *   1) tries the standard named exports (works on unprotected / other builds), and
 *   2) falls back to an offsets file (offsets/offsets.json) where a researcher can
 *      supply module-relative addresses obtained from a static dump.
 * It NEVER modifies il2cpp state; it only reads names for logging.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var ICFG = CFG.il2cpp || {};
  var P = 'B';
  var MOD = 'libil2cpp.so';

  var API = [
    'il2cpp_init', 'il2cpp_runtime_invoke', 'il2cpp_class_from_name',
    'il2cpp_method_get_name', 'il2cpp_resolve_icall', 'il2cpp_string_new',
    'il2cpp_string_new_len', 'il2cpp_domain_get', 'il2cpp_string_chars',
    'il2cpp_type_get_name', 'il2cpp_class_get_name', 'il2cpp_class_get_namespace'
  ];

  var invokeSeen = new U.DedupSet(8192);
  var icallSeen = new U.DedupSet(8192);
  var kw = (ICFG.invoke_keyword_filter || []);

  function resolveAll() {
    var found = {}, missing = [];
    if (ICFG.try_named_exports !== false) {
      API.forEach(function (n) {
        var p = U.exp(MOD, n);
        if (p) found[n] = p; else missing.push(n);
      });
    } else { missing = API.slice(); }

    // offsets fallback
    var off = (globalThis.KS_OFFSETS && globalThis.KS_OFFSETS[MOD]) || {};
    var base = null;
    try { var m = Process.findModuleByName(MOD); if (m) base = m.base; } catch (e) {}
    if (base) {
      missing.slice().forEach(function (n) {
        if (off[n]) {
          try {
            found[n] = base.add(ptr(off[n]));
            missing.splice(missing.indexOf(n), 1);
          } catch (e) {}
        }
      });
    }
    S.il2cpp.ptrs = found;
    KS.log.important(P, 'il2cpp_api_resolved', {
      module: MOD, base: base ? base.toString() : null,
      resolved: Object.keys(found), missing: missing,
      note: missing.length ? 'missing symbols are expected on HTProtect builds — supply RVAs in offsets/offsets.json' : 'all named exports present'
    });
    return found;
  }

  function nf(ptr_, ret, args) { try { return new NativeFunction(ptr_, ret, args); } catch (e) { return null; } }

  function buildHelpers(f) {
    var h = {};
    if (f.il2cpp_method_get_name) h.method_get_name = nf(f.il2cpp_method_get_name, 'pointer', ['pointer']);
    if (f.il2cpp_class_get_name) h.class_get_name = nf(f.il2cpp_class_get_name, 'pointer', ['pointer']);
    if (f.il2cpp_string_chars) h.string_chars = nf(f.il2cpp_string_chars, 'pointer', ['pointer']);
    S.il2cpp.helpers = h;
    return h;
  }

  function hook(f, h) {
    if (f.il2cpp_init) U.attachSafe('il2cpp_init', f.il2cpp_init, {
      onEnter: function () { KS.log.important(P, 'il2cpp_init', { ts: KS.log.now() }); }
    });

    if (f.il2cpp_class_from_name) U.attachSafe('il2cpp_class_from_name', f.il2cpp_class_from_name, {
      onEnter: function (args) {
        var ns = U.readCStr(args[1], 256), nm = U.readCStr(args[2], 256);
        KS.log.event(P, 'class_from_name', { ns: ns, name: nm });
      }
    });

    if (f.il2cpp_resolve_icall) U.attachSafe('il2cpp_resolve_icall', f.il2cpp_resolve_icall, {
      onEnter: function (args) {
        var name = U.readCStr(args[0], 256);
        if (name && !icallSeen.seen(name)) {
          KS.log.event(P, 'resolve_icall', { icall: name });
          KS.bus.emit('icall', { name: name });
        }
      }
    });

    if (f.il2cpp_runtime_invoke && h.method_get_name) {
      var mode = ICFG.invoke_log_mode || 'distinct';
      U.attachSafe('il2cpp_runtime_invoke', f.il2cpp_runtime_invoke, {
        onEnter: function (args) {
          try {
            var nmPtr = h.method_get_name(args[0]);
            var nm = U.readCStr(nmPtr, 128);
            if (!nm) return;
            var interesting = kw.length === 0 || kw.some(function (k) { return nm.toLowerCase().indexOf(k.toLowerCase()) !== -1; });
            if (!interesting) return;
            if (mode === 'distinct' && invokeSeen.seen(nm)) return;
            KS.log.event(P, 'runtime_invoke', { method: nm });
          } catch (e) {}
        }
      });
      KS.log.event(P, 'runtime_invoke_hooked', { mode: mode, filter: kw });
    }
  }

  KS.phaseB = {
    init: function () {
      var f = resolveAll();
      if (Object.keys(f).length === 0) {
        KS.log.important(P, 'phase_degraded', {
          reason: 'no il2cpp API resolved (encrypted exports). Phases H/G that depend on il2cpp_string_new are limited until offsets are provided.',
          how_to: 'Add offsets/offsets.json: {"libil2cpp.so": {"il2cpp_string_new":"0x...", "il2cpp_runtime_invoke":"0x..."}}'
        });
        return;
      }
      var h = buildHelpers(f);
      hook(f, h);
      KS.log.important(P, 'phase_ready', { resolved: Object.keys(f).length });
    }
  };
})();
