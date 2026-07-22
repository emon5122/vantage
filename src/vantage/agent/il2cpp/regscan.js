/*
 * il2cpp/regscan.js — locate Il2CppCodeRegistration / Il2CppMetadataRegistration
 * structurally (Objective 2), for documentation of the registration flow. This
 * READS libil2cpp's writable data segments looking for the registration structs'
 * signature; it does not modify anything and does not decrypt metadata.
 *
 * Technique (well-known, from Il2CppDumper's dynamic mode):
 *   Il2CppCodeRegistration ends with several {count(int), pointer-to-array}
 *   pairs where the pointers target arrays of function pointers inside
 *   libil2cpp's executable range. Il2CppMetadataRegistration similarly holds
 *   {count, pointer} pairs targeting the (writable) type/metadata tables.
 * We scan .data/.data.rel.ro for a run of such (count, ptr-into-module) pairs
 * and report the strongest candidates. This is a HEURISTIC locator; results are
 * reported as candidates with a confidence, never as ground truth.
 *
 * If the IL2CPP API is already located (api_locator), this module is optional
 * (the API alone yields the full type system). It exists to satisfy the
 * "locate CodeRegistration/MetadataRegistration without exported symbols"
 * objective and to help bootstrap offsets on a decrypted dump.
 */
(function () {
  var S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var RC = (CFG.il2cpp_recovery || {});
  var P = 'B4';
  var MOD = 'libil2cpp.so';

  function moduleRanges() {
    var m = Process.findModuleByName(MOD);
    if (!m) return null;
    var ranges = m.enumerateRanges('r--').concat(m.enumerateRanges('rw-'));
    var exec = m.enumerateRanges('r-x');
    return { base: m.base, size: m.size, data: ranges, exec: exec, end: m.base.add(m.size) };
  }

  function inModule(p, mr) { return p.compare(mr.base) >= 0 && p.compare(mr.end) < 0; }
  function inExec(p, mr) { for (var i = 0; i < mr.exec.length; i++) { var r = mr.exec[i]; if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) return true; } return false; }

  // Count consecutive {int32 count, pointer} pairs where pointer targets an
  // array of module pointers. Returns a heuristic score.
  function scorePairsAt(addr, mr, wantExec) {
    var ps = Process.pointerSize, pairs = 0;
    try {
      for (var i = 0; i < 12; i++) {
        var cnt = addr.add(i * (4 + ps) + 0).readU32();
        var arrp = addr.add(i * (4 + ps) + (ps === 8 ? 8 : 4)).readPointer(); // account for alignment
        if (cnt === 0 || cnt > 2000000) break;
        if (arrp.isNull() || !inModule(arrp, mr)) break;
        // sample first array element -> should be a module pointer (exec for CodeReg)
        var first = arrp.readPointer();
        if (!inModule(first, mr)) break;
        if (wantExec && !inExec(first, mr)) break;
        pairs++;
      }
    } catch (e) {}
    return pairs;
  }

  KS.il2cppRegScan = {
    run: function () {
      if (RC.regscan === false) { KS.log.event(P, 'regscan_skipped', {}); return; }
      var mr = moduleRanges();
      if (!mr) { KS.log.error(P, 'regscan_no_module', {}); return; }
      KS.log.important(P, 'regscan_start', { module: MOD, base: mr.base.toString(), data_ranges: mr.data.length });
      var ps = Process.pointerSize, stride = ps;
      var code = [], meta = [];
      var scanned = 0, cap = RC.regscan_max_words || (2 * 1024 * 1024);
      mr.data.forEach(function (r) {
        var a = r.base, end = r.base.add(r.size);
        while (a.compare(end) < 0 && scanned < cap) {
          var codeScore = scorePairsAt(a, mr, true);   // CodeRegistration -> exec ptrs
          var metaScore = scorePairsAt(a, mr, false);  // MetadataRegistration -> data ptrs
          if (codeScore >= 4) code.push({ addr: a.toString(), rva: '0x' + a.sub(mr.base).toString(16), pairs: codeScore });
          if (metaScore >= 5) meta.push({ addr: a.toString(), rva: '0x' + a.sub(mr.base).toString(16), pairs: metaScore });
          a = a.add(stride); scanned++;
        }
      });
      code.sort(function (x, y) { return y.pairs - x.pairs; });
      meta.sort(function (x, y) { return y.pairs - x.pairs; });
      KS.log.important(P, 'regscan_result', {
        scanned_words: scanned,
        code_registration_candidates: code.slice(0, 5),
        metadata_registration_candidates: meta.slice(0, 5),
        note: 'heuristic candidates. Cross-check the top CodeRegistration against il2cpp_init xrefs on a static dump before trusting.'
      });
      S.il2cpp.regscan = { code: code.slice(0, 5), meta: meta.slice(0, 5) };
    }
  };
})();
