/*
 * Process discovery.
 * Unity version, loaded libraries + load order, dlopen / android_dlopen_ext,
 * per-library JNI_OnLoad, and (observation-only) JNI RegisterNatives mapping.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var interest = new Set(CFG.modules_of_interest || []);
  var jniHooked = new Set();
  var P = 'A';

  function recordModule(name, base, path) {
    var seq = ++S.moduleSeq;
    var entry = { name: name, base: base ? base.toString() : null, seq: seq, path: path || null, ts: KS.log.now() };
    S.modules.push(entry);
    KS.log.event(P, 'library_loaded', entry, { important: interest.has(name) });
    hookJniOnLoad(name);
    KS.bus.emit('module_loaded', { name: name, base: base });
  }

  function snapshotModules() {
    Process.enumerateModules().forEach(function (m) { recordModule(m.name, m.base, m.path); });
    KS.log.important(P, 'module_snapshot_done', { count: S.modules.length });
  }

  function detectUnityVersion() {
    // 1) Java: app versionName + try UnityPlayer
    try {
      if (Java.available) {
        Java.perform(function () {
          try {
            var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var pm = ctx.getPackageManager();
            var pkg = ctx.getPackageName();
            var pi = pm.getPackageInfo(pkg, 0);
            KS.log.important(P, 'app_version', { package: pkg, versionName: pi.versionName.value, versionCode: pi.versionCode.value });
          } catch (e) {}
        });
      }
    } catch (e) {}
    // 2) Native: scan libmain.so / libunity.so rodata for a Unity version token like 2022.3.62f1
    ['libmain.so', 'libunity.so'].forEach(function (mod) {
      try {
        var m = Process.findModuleByName(mod);
        if (!m) return;
        var pat = '32 30 32 ??'; // "202x" — cheap anchor; refine by regex on the surrounding string
        Memory.scan(m.base, Math.min(m.size, 0x400000), pat, {
          onMatch: function (addr) {
            var s = U.readCStr(addr, 32);
            if (s && /^\d{4}\.\d+\.\d+[fpba]\d+/.test(s)) {
              KS.log.important(P, 'unity_version', { module: mod, version: s });
              return 'stop';
            }
          },
          onError: function () {},
          onComplete: function () {}
        });
      } catch (e) {}
    });
  }

  function hookJniOnLoad(moduleName) {
    if (jniHooked.has(moduleName)) return;
    var p = U.exp(moduleName, 'JNI_OnLoad');
    if (!p) return;
    jniHooked.add(moduleName);
    U.attachSafe(moduleName + '!JNI_OnLoad', p, {
      onEnter: function () {
        KS.log.important(P, 'JNI_OnLoad_enter', { module: moduleName, ts: KS.log.now() });
      },
      onLeave: function (ret) {
        KS.log.important(P, 'JNI_OnLoad_leave', { module: moduleName, jni_version: '0x' + ret.toInt32().toString(16) });
      }
    });
  }

  function hookLoaders() {
    // android_dlopen_ext is what System.loadLibrary uses on modern Android.
    ['android_dlopen_ext', 'dlopen', '__loader_dlopen'].forEach(function (fn) {
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.path = U.readCStr(args[0], 512); },
        onLeave: function (ret) {
          var name = this.path ? this.path.split('/').pop() : '?';
          KS.log.event(P, 'dlopen', { fn: fn, path: this.path, handle: ret.toString() }, { important: interest.has(name) });
          // A newly dlopen'd lib may not be in Process.modules until now — re-check.
          try {
            var m = Process.findModuleByName(name);
            if (m && !S.modules.some(function (x) { return x.name === name; })) recordModule(m.name, m.base, m.path);
            else hookJniOnLoad(name);
          } catch (e) {}
        }
      });
      KS.log.event(P, 'loader_hooked', { fn: fn });
    });
  }

  // Observation-only JNI RegisterNatives logging (reveals native entry points,
  // incl. HTProtect/nesec dynamic registration). Reads the JNINativeMethod
  // table; never modifies it.
  function hookRegisterNatives() {
    try {
      if (!Java.available) return;
      Java.perform(function () {
        var env = Java.vm.getEnv();
        var vtable = env.handle.readPointer();
        var RN = vtable.add(215 * U.ptrSize).readPointer(); // JNINativeInterface.RegisterNatives
        U.attachSafe('JNIEnv->RegisterNatives', RN, {
          onEnter: function (args) {
            try {
              var methods = args[2];
              var count = args[3].toInt32();
              var owner = U.moduleOf(this.returnAddress) || {};
              var list = [];
              for (var i = 0; i < Math.min(count, 64); i++) {
                var e = methods.add(i * 3 * U.ptrSize);
                var nm = U.readCStr(e.readPointer(), 128);
                var sig = U.readCStr(e.add(U.ptrSize).readPointer(), 256);
                var fn = e.add(2 * U.ptrSize).readPointer();
                list.push({ name: nm, sig: sig, fn: fn.toString(), fn_mod: (U.moduleOf(fn) || {}).name });
              }
              KS.log.important(P, 'RegisterNatives', { registrant_module: owner.name, count: count, methods: list });
            } catch (e) { KS.log.error(P, 'RegisterNatives_parse', { err: String(e) }); }
          }
        });
        KS.log.event(P, 'register_natives_hooked', {});
      });
    } catch (e) { KS.log.error(P, 'register_natives_hook', { err: String(e) }); }
  }

  KS.phaseA = {
    init: function () {
      hookLoaders();          // catch future loads first (esp. in spawn mode)
      snapshotModules();      // record what is already mapped
      detectUnityVersion();
      hookRegisterNatives();
      KS.log.important(P, 'phase_ready', { modules: S.modules.length });
    }
  };
})();
