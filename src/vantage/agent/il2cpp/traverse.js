/*
 * il2cpp/traverse.js — walk the in-memory managed type system using the located
 * read-only API. Streams records: Assembly -> Image -> Class -> Method.
 *
 * Emits (via KS.log) one 'class' event per class and 'method' rows folded into
 * it (capped). The host reducer (analyze_metadata.py) rebuilds the JSON tree.
 *
 * OBSERVATION-ONLY. All calls are read accessors. Method RVAs come from reading
 * MethodInfo.methodPointer (a read); nothing is written or freed.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var RC = (CFG.il2cpp_recovery || {});
  var P = 'B4';
  var D = KS.il2cppDefs;

  function readStr(p) { return U.readCStr(p, 400); }

  function enumMethods(fns, klass, base, cap) {
    var out = [];
    try {
      var iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(ptr(0));
      var m;
      var n = 0;
      while (!(m = fns.il2cpp_class_get_methods(klass, iter)).isNull()) {
        var name = readStr(fns.il2cpp_method_get_name(m));
        var pc = fns.il2cpp_method_get_param_count ? fns.il2cpp_method_get_param_count(m) : null;
        var rt = null;
        try { if (fns.il2cpp_method_get_return_type) rt = D.typeName(fns, fns.il2cpp_method_get_return_type(m)); } catch (e) {}
        var params = [];
        if (RC.method_params !== false && pc && fns.il2cpp_method_get_param) {
          for (var i = 0; i < Math.min(pc, 16); i++) {
            try { params.push(D.typeName(fns, fns.il2cpp_method_get_param(m, i))); } catch (e) { params.push(null); }
          }
        }
        var flags = null;
        try { if (fns.il2cpp_method_get_flags) { var ip = Memory.alloc(4); flags = fns.il2cpp_method_get_flags(m, ip); } } catch (e) {}
        out.push({
          name: name, param_count: pc, return_type: rt, params: params,
          flags: flags, rva: D.methodRva(m, base)
        });
        if (++n >= (cap || 512)) break;
      }
    } catch (e) { KS.log.error(P, 'enum_methods', { err: String(e) }); }
    return out;
  }

  KS.il2cppTraverse = {
    run: function (opts) {
      opts = opts || {};
      var fns = S.il2cpp.fns;
      if (!fns) { KS.log.error(P, 'traverse_no_api', {}); return; }
      var base = S.il2cpp.base;
      var maxClasses = opts.max_classes || RC.max_classes || 200000;
      var methodCap = opts.method_cap || RC.method_cap || 512;
      var namesOnly = !!opts.names_only;

      var domain = fns.il2cpp_domain_get();
      var sizePtr = Memory.alloc(Process.pointerSize); sizePtr.writePointer(ptr(0));
      var asmArr = fns.il2cpp_domain_get_assemblies(domain, sizePtr);
      var acount = Process.pointerSize === 8 ? sizePtr.readU64().valueOf() : sizePtr.readU32();
      KS.log.important(P, 'traverse_start', { assemblies: acount, max_classes: maxClasses, names_only: namesOnly });

      var totalClasses = 0, totalMethods = 0, images = [];
      for (var a = 0; a < acount; a++) {
        var asm = asmArr.add(a * Process.pointerSize).readPointer();
        if (asm.isNull()) continue;
        var img = fns.il2cpp_assembly_get_image(asm);
        var imgName = readStr(fns.il2cpp_image_get_name(img));
        var ccount = fns.il2cpp_image_get_class_count(img);
        images.push({ image: imgName, classes: ccount });
        KS.log.event(P, 'image', { image: imgName, class_count: ccount, index: a });

        for (var c = 0; c < ccount && totalClasses < maxClasses; c++) {
          var klass = fns.il2cpp_image_get_class(img, c);
          if (klass.isNull()) continue;
          var cn = readStr(fns.il2cpp_class_get_name(klass));
          var ns = readStr(fns.il2cpp_class_get_namespace(klass));
          totalClasses++;
          var rec = { assembly: imgName, ns: ns, name: cn };
          if (!namesOnly) {
            var methods = enumMethods(fns, klass, base, methodCap);
            totalMethods += methods.length;
            rec.method_count = methods.length;
            rec.methods = methods;
            try { rec.flags = fns.il2cpp_class_get_flags ? fns.il2cpp_class_get_flags(klass) : null; } catch (e) {}
          }
          // Stream to classifier/correlator + host.
          KS.bus.emit('managed_class', rec);
          KS.log.event(P, 'class', namesOnly ? rec : {
            assembly: rec.assembly, ns: rec.ns, name: rec.name, method_count: rec.method_count,
            methods: rec.methods // reducer keeps full detail; console truncates
          });
        }
      }
      KS.log.important(P, 'traverse_done', { assemblies: acount, images: images.length, classes: totalClasses, methods: totalMethods });
      S.il2cpp.stats = { assemblies: acount, classes: totalClasses, methods: totalMethods, images: images };
    }
  };
})();
