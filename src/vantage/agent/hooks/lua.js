/*
 * Lua (tolua# / LuaJIT 2.1) observation.
 * Detect VM creation, chunk loading (script names), pcall execution, and global
 * access. Reveals loaded Lua script names + whether chunks are source or
 * precompiled LuaJIT bytecode (first byte 0x1B). Read-only.
 *
 * LuaJIT symbol notes:
 *   - lua_getglobal / lua_setglobal are macros over lua_getfield/lua_setfield
 *     with LUA_GLOBALSINDEX; we hook the exported lua_getfield/lua_setfield.
 *   - tolua# statically links LuaJIT into libtolua.so; some symbols may be local
 *     rather than exported — utils.exp() also scans the symbol table.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var L = CFG.lua || {};
  var P = 'I';
  var MOD = L.module || 'libtolua.so';
  var seenChunk = new U.DedupSet(8192);
  var gkw = (L.global_keyword_filter || []).map(function (s) { return s.toLowerCase(); });

  function chunkKind(buf) {
    try { var b = buf.readU8(); return b === 0x1b ? 'luajit_bytecode' : 'lua_source'; } catch (e) { return 'unknown'; }
  }

  function hookLoad() {
    ['luaL_loadbuffer', 'luaL_loadbufferx'].forEach(function (fn) {
      var p = U.exp(MOD, fn) || U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) {
          try {
            var buf = args[1], sz = args[2].toInt32(), name = U.readCStr(args[3], 256);
            var key = (name || '?') + ':' + sz;
            if (seenChunk.seen(key)) return;
            KS.log.important(P, 'lua_load', { fn: fn, chunk: name, size: sz, kind: chunkKind(buf), bt: U.backtrace(this.context, 'lua_load') });
          } catch (e) {}
        }
      });
      KS.log.event(P, 'load_hooked', { fn: fn });
    });
    ['luaL_loadfile', 'luaL_loadfilex', 'luaL_loadstring'].forEach(function (fn) {
      var p = U.exp(MOD, fn) || U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { var s = U.readCStr(args[1], 256); KS.log.important(P, 'lua_load', { fn: fn, chunk: s }); }
      });
    });
  }

  function hookVm() {
    ['luaL_newstate', 'lua_newstate'].forEach(function (fn) {
      var p = U.exp(MOD, fn) || U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onLeave: function (ret) { KS.log.important(P, 'lua_vm_created', { fn: fn, L: ret.toString(), ts: KS.log.now() }); }
      });
    });
  }

  function hookPcall() {
    if (!L.log_pcall) return;
    ['lua_pcall', 'lua_pcallk'].forEach(function (fn) {
      var p = U.exp(MOD, fn) || U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function () { KS.count('lua_pcall'); }
      });
    });
    setInterval(function () { if (S.counters.lua_pcall) KS.log.event(P, 'lua_pcall_count', { total: S.counters.lua_pcall }); }, 15000);
  }

  function hookGlobals() {
    if (!L.log_globals) return;
    ['lua_getfield', 'lua_setfield'].forEach(function (fn) {
      var p = U.exp(MOD, fn) || U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) {
          try {
            var name = U.readCStr(args[2], 128);
            if (!name) return;
            var low = name.toLowerCase();
            if (gkw.length && !gkw.some(function (k) { return low.indexOf(k) !== -1; })) return;
            KS.log.event(P, 'lua_global', { fn: fn, name: name });
          } catch (e) {}
        }
      });
    });
  }

  KS.phaseI = {
    init: function () {
      if (!Process.findModuleByName(MOD)) {
        KS.log.important(P, 'lua_module_absent', { module: MOD, note: 'will retry when loaded' });
        KS.bus.on('module_loaded', function (d) { if (d.name === MOD) KS.phaseI._wire(); });
        return;
      }
      KS.phaseI._wire();
    },
    _wire: function () { hookVm(); hookLoad(); hookPcall(); hookGlobals(); KS.log.important(P, 'phase_ready', { module: MOD }); }
  };
})();
