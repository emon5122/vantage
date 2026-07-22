/*
 * core/utils.js — shared helpers used by all phases.
 * Pure read/observe helpers. Nothing here writes target memory.
 */
(function () {
  var CFG = (globalThis.KS_CONFIG || {});
  var LIM = (CFG.limits || {});
  var BT_DEPTH = LIM.backtrace_depth || 12;

  function attachSafe(name, target, callbacks) {
    if (target === null || typeof target === 'undefined' || target.isNull()) {
      KS.log.error('UTIL', 'attach_skip', { name: name, reason: 'target null' });
      return false;
    }
    try {
      Interceptor.attach(target, callbacks);
      return true;
    } catch (e) {
      KS.log.error('UTIL', 'attach_fail', { name: name, err: String(e) });
      return false;
    }
  }

  // Resolve an export in a module, tolerant across Frida versions and stripping.
  function exp(moduleName, symbol) {
    try {
      var p = Module.findExportByName(moduleName, symbol);
      if (p && !p.isNull()) return p;
    } catch (e) {}
    // fall back to a symbol-table scan (helps with non-exported but symbolized funcs)
    try {
      if (moduleName) {
        var m = Process.findModuleByName(moduleName);
        if (m) {
          var syms = m.enumerateSymbols();
          for (var i = 0; i < syms.length; i++) {
            if (syms[i].name === symbol && syms[i].address && !syms[i].address.isNull())
              return syms[i].address;
          }
        }
      }
    } catch (e2) {}
    return null;
  }

  function readCStr(ptr, max) {
    try {
      if (!ptr || ptr.isNull()) return null;
      return ptr.readUtf8String(max || 512);
    } catch (e) {
      try { return ptr.readCString(max || 512); } catch (e2) { return null; }
    }
  }

  function hexPreview(ptr, len) {
    try {
      if (!ptr || ptr.isNull() || len <= 0) return null;
      var n = Math.min(len, 64);
      var bytes = new Uint8Array(ptr.readByteArray(n));
      var hex = '', asc = '';
      for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i];
        hex += ('0' + b.toString(16)).slice(-2);
        asc += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
      }
      return { hex: hex, ascii: asc, shown: n, total: len };
    } catch (e) { return null; }
  }

  function backtrace(context, tag) {
    try {
      var onList = (LIM.backtrace_on || []);
      if (tag && onList.indexOf(tag) === -1) return null;
      var bt = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, BT_DEPTH);
      return bt.map(function (a) {
        var sym = DebugSymbol.fromAddress(a);
        return { addr: a.toString(), sym: sym ? (sym.moduleName + '!' + (sym.name || '?') + '+0x' + (sym.address ? a.sub(sym.address).toString(16) : '?')) : '?' };
      });
    } catch (e) { return null; }
  }

  function moduleOf(addr) {
    try {
      var m = Process.findModuleByAddress(ptr(addr));
      return m ? { name: m.name, base: m.base.toString(), off: '0x' + ptr(addr).sub(m.base).toString(16) } : null;
    } catch (e) { return null; }
  }

  // Simple dedup set with cap to avoid unbounded growth.
  function DedupSet(cap) {
    this.cap = cap || 4096; this.s = new Set();
  }
  DedupSet.prototype.seen = function (k) {
    if (this.s.has(k)) return true;
    if (this.s.size >= this.cap) this.s.clear();
    this.s.add(k); return false;
  };

  globalThis.KS = globalThis.KS || {};
  KS.utils = {
    attachSafe: attachSafe,
    exp: exp,
    readCStr: readCStr,
    hexPreview: hexPreview,
    backtrace: backtrace,
    moduleOf: moduleOf,
    DedupSet: DedupSet,
    ptrSize: Process.pointerSize,
    is64: Process.pointerSize === 8
  };
})();
