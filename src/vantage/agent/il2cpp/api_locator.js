/*
 * il2cpp/api_locator.js — locate the IL2CPP public API when export NAMES are
 * encrypted by HTProtect. Layered, from most to least reliable, each result
 * gated by a behavioral validation battery before the API is trusted.
 *
 * Locators:
 *   L1 named exports        — works on unprotected/other builds (fails here).
 *   L2 offsets file         — RVAs from a static dump you are authorized to make
 *                             (offsets/offsets.json). MOST RELIABLE on HTProtect.
 *   L3 export-index auto-map — map libil2cpp FUNC exports to the canonical order,
 *                             then VALIDATE behaviorally. Opt-in (probes call
 *                             unknown addresses); default off.
 *   L4 registration scan    — locate Il2CppCodeRegistration / MetadataRegistration
 *                             structurally (for the report / method tables).
 *
 * OBSERVATION-ONLY: no writes, no decryption, no key extraction. L3 is gated
 * behind config.il2cpp_recovery.allow_behavioral_probe because blind-calling an
 * unknown pointer could crash or be flagged; default is the safe offsets path.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var RC = (CFG.il2cpp_recovery || {});
  var P = 'B4';
  var MOD = 'libil2cpp.so';
  var NEEDED = Object.keys(KS.il2cppDefs.SIG);

  function moduleBase() { try { var m = Process.findModuleByName(MOD); return m ? m.base : null; } catch (e) { return null; } }

  function L1_named() {
    var out = {}, n = 0;
    NEEDED.forEach(function (name) { var p = U.exp(MOD, name); if (p) { out[name] = p; n++; } });
    return { name: 'L1_named_exports', found: out, count: n };
  }

  function L2_offsets() {
    var out = {}, n = 0;
    var base = moduleBase();
    var off = (globalThis.KS_OFFSETS && globalThis.KS_OFFSETS[MOD]) || {};
    if (base) NEEDED.forEach(function (name) {
      if (off[name]) { try { out[name] = base.add(ptr(off[name])); n++; } catch (e) {} }
    });
    return { name: 'L2_offsets_file', found: out, count: n };
  }

  function L3_export_index() {
    // Map FUNC exports (in symbol-table order) to the canonical il2cpp order.
    // This preserves ADDRESSES (intact) while ignoring the scrambled NAME
    // strings, then validates. Purely a candidate generator.
    var out = {};
    var base = moduleBase();
    if (!base) return { name: 'L3_export_index', found: {}, count: 0, note: 'no module' };
    var exps;
    try { exps = Process.getModuleByName(MOD).enumerateExports(); }
    catch (e) { try { exps = Process.findModuleByName(MOD).enumerateExports(); } catch (e2) { exps = []; } }
    var funcs = exps.filter(function (e) { return e.type === 'function'; });
    var order = KS.il2cppDefs.CANONICAL_ORDER_HINT;
    // Heuristic: if export count is in the plausible il2cpp API range, align by
    // index. This is intentionally conservative and validated afterwards.
    KS.log.event(P, 'L3_survey', { func_exports: funcs.length, canonical_hint: order.length });
    if (funcs.length >= 60 && funcs.length <= 1000) {
      for (var i = 0; i < Math.min(funcs.length, order.length); i++) {
        if (!out[order[i]]) out[order[i]] = funcs[i].address;
      }
    }
    return { name: 'L3_export_index_automap', found: out, count: Object.keys(out).length, note: 'candidate mapping — must pass validation' };
  }

  // Behavioral validation: safely exercise a tiny slice of the API and confirm
  // the results are structurally sane. Any exception/insane value => reject.
  function validate(fns) {
    try {
      if (!fns.il2cpp_domain_get || !fns.il2cpp_domain_get_assemblies ||
          !fns.il2cpp_assembly_get_image || !fns.il2cpp_image_get_class_count) return { ok: false, reason: 'missing core fns' };
      var domain = fns.il2cpp_domain_get();
      if (!domain || domain.isNull()) return { ok: false, reason: 'domain null' };
      if (Process.findRangeByAddress(domain) === null) return { ok: false, reason: 'domain not mapped' };
      var sizePtr = Memory.alloc(Process.pointerSize);
      var asmArr = fns.il2cpp_domain_get_assemblies(domain, sizePtr);
      var count = sizePtr.readULong ? sizePtr.readULong().valueOf() : sizePtr.readU32();
      if (!asmArr || asmArr.isNull() || count < 1 || count > 5000) return { ok: false, reason: 'assembly count insane: ' + count };
      var asm0 = asmArr.readPointer();
      if (asm0.isNull()) return { ok: false, reason: 'assembly[0] null' };
      var img = fns.il2cpp_assembly_get_image(asm0);
      if (!img || img.isNull()) return { ok: false, reason: 'image null' };
      var cc = fns.il2cpp_image_get_class_count(img);
      if (cc < 1 || cc > 200000) return { ok: false, reason: 'class count insane: ' + cc };
      // read one class name if we can
      var sampleName = null;
      if (fns.il2cpp_image_get_class && fns.il2cpp_class_get_name) {
        var k = fns.il2cpp_image_get_class(img, 0);
        if (k && !k.isNull()) sampleName = U.readCStr(fns.il2cpp_class_get_name(k), 128);
      }
      return { ok: true, assemblies: count, first_image_classes: cc, sample_class: sampleName };
    } catch (e) { return { ok: false, reason: 'exception: ' + String(e) }; }
  }

  function inExec(p) {
    try { var r = Process.findRangeByAddress(p); return r && r.protection.indexOf('x') !== -1; } catch (e) { return false; }
  }

  function tryLocator(res) {
    if (res.count === 0) { KS.log.event(P, 'locator_empty', { locator: res.name }); return null; }
    // sanity: pointers must be executable & inside a module
    var bad = 0;
    Object.keys(res.found).forEach(function (k) { if (!inExec(res.found[k])) bad++; });
    var fns = KS.il2cppDefs.build(res.found);
    var v = validate(fns);
    KS.log.important(P, 'locator_result', { locator: res.name, resolved: Object.keys(res.found).length, nonexec_ptrs: bad, validation: v });
    if (v.ok) { S.il2cpp.ptrs = res.found; S.il2cpp.fns = fns; S.il2cpp.locator = res.name; S.il2cpp.base = moduleBase(); return { fns: fns, validation: v, locator: res.name }; }
    return null;
  }

  KS.il2cppLocator = {
    locate: function () {
      var base = moduleBase();
      KS.log.important(P, 'locate_start', { module: MOD, base: base ? base.toString() : null });

      // L1 then L2 (safe, no blind calls beyond validation of resolved ptrs).
      var r = tryLocator(L1_named());
      if (r) return r;
      r = tryLocator(L2_offsets());
      if (r) return r;

      // L3 opt-in behavioral probe.
      if (RC.allow_behavioral_probe) {
        KS.log.important(P, 'behavioral_probe', { warning: 'calling unknown addresses (opt-in). May crash or be flagged by HTProtect.' });
        r = tryLocator(L3_export_index());
        if (r) return r;
      } else {
        KS.log.important(P, 'L3_skipped', { reason: 'allow_behavioral_probe=false (default). Provide offsets/offsets.json or enable probing explicitly.' });
      }

      KS.log.important(P, 'locate_failed', {
        reason: 'IL2CPP API not located without names.',
        remedy: 'Add RVAs to offsets/offsets.json (from an authorized static dump) OR set il2cpp_recovery.allow_behavioral_probe=true to try L3.'
      });
      return null;
    }
  };
})();
