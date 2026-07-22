/*
 * Asset loading observation.
 * Records AssetBundle file access, AssetBundle/TextAsset/Resources icalls,
 * and (when il2cpp API is available) high-level asset load method invocations.
 *
 * On this target bundle payloads are ENCRYPTED (custom UnityFS layer). We do NOT
 * decrypt them; we log which bundle files/paths are touched and which asset
 * load APIs fire. TextAsset/Lua/JSON/ScriptableObject contents become visible
 * only after the game's own loader decrypts them in managed memory — those are
 * surfaced by Phase H (il2cpp strings) and Phase I (Lua), not here.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var P = 'G';
  var seenBundle = new U.DedupSet(8192);

  function looksBundle(path) {
    if (!path) return false;
    var low = path.toLowerCase();
    return low.indexOf('.unity3d') !== -1 || low.indexOf('/assets/data/') !== -1 ||
           low.indexOf('bundle') !== -1 || low.indexOf('/il2cpp/') !== -1;
  }

  // File-level bundle access (open/fopen already hooked in C for metadata; here
  // we add a bundle-focused open watcher without double-logging metadata).
  function hookBundleOpen() {
    [['open', 0], ['openat', 1]].forEach(function (pair) {
      var fn = pair[0], idx = pair[1];
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe('G:' + fn, p, {
        onEnter: function (args) { this.path = U.readCStr(args[idx], 512); this.b = looksBundle(this.path); },
        onLeave: function (ret) {
          if (!this.b) return;
          var base = this.path.split('/').pop();
          if (seenBundle.seen(base)) return;
          KS.log.important(P, 'bundle_file_open', { path: this.path, bundle: base, fd: ret.toInt32(), bt: U.backtrace(this.context, 'assetbundle') });
        }
      });
    });
  }

  // Correlate with il2cpp icalls (Phase B emits 'icall'): AssetBundle.*,
  // Resources.Load, TextAsset.* resolutions reveal the managed asset pipeline.
  function hookIcallHints() {
    KS.bus.on('icall', function (d) {
      var n = d.name || '';
      if (/AssetBundle|TextAsset|Resources::Load|WWW|UnityWebRequest|StreamingAssets/i.test(n)) {
        KS.log.important(P, 'asset_icall', { icall: n });
      }
    });
  }

  // OPTIONAL: hook AssetBundle load methods directly if il2cpp API + offsets are
  // available. Uses il2cpp_class_from_name + il2cpp_class_get_method_from_name,
  // resolved only if present. Purely read-only logging of arguments.
  function hookAssetBundleMethods() {
    var f = (S.il2cpp && S.il2cpp.ptrs) || {};
    if (!f.il2cpp_class_from_name || !f.il2cpp_domain_get) {
      KS.log.event(P, 'assetbundle_methods_skipped', { reason: 'il2cpp API not resolved (encrypted exports) — relying on file + icall observation' });
      return;
    }
    // Left as an extension point: resolving UnityEngine.AssetBundle methods
    // requires il2cpp_class_get_method_from_name + assembly image; wire these in
    // once offsets are supplied. See docs/DIAGRAMS.md "Extending the instrumentation".
    KS.log.event(P, 'assetbundle_methods_available', { note: 'il2cpp API present — extend here with class_get_method_from_name' });
  }

  KS.phaseG = {
    init: function () {
      hookBundleOpen();
      hookIcallHints();
      hookAssetBundleMethods();
      KS.log.important(P, 'phase_ready', {});
    }
  };
})();
