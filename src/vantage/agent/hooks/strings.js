/*
 * Runtime string recovery.
 * The highest-value observation path on an HTProtect target: even though the
 * metadata (and therefore string literals) are encrypted at rest, the game
 * calls il2cpp_string_new(char*) with DECRYPTED C strings at runtime. Hooking
 * it recovers runtime hostnames, URLs, config keys, tokens, etc. WITHOUT
 * defeating any protection — we only read arguments already in the clear.
 *
 * Also (optional) scans std::string construction is not hooked globally (too
 * noisy / detectable); instead a targeted keyword filter is applied to
 * il2cpp_string_new + il2cpp_string_new_len.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var H = CFG.strings || {};
  var P = 'H';
  var kws = (H.keywords || []).map(function (k) { return k.toLowerCase(); });
  var maxLen = H.max_len || 512;
  var dedup = H.dedup !== false ? new U.DedupSet(16384) : null;

  function interesting(s) {
    if (!s) return false;
    var low = s.toLowerCase();
    for (var i = 0; i < kws.length; i++) if (low.indexOf(kws[i]) !== -1) return true;
    return false;
  }

  function emit(kind, s) {
    if (!interesting(s)) return;
    if (dedup && dedup.seen(kind + '|' + s)) return;
    KS.log.important(P, 'string', { via: kind, value: s.length > maxLen ? s.slice(0, maxLen) + '…' : s });
    // feed request classifier if it looks like an endpoint
    if (/^wss?:|^https?:|gateway|serverlist|\.com|\.net|\.cn/i.test(s)) KS.bus.emit('endpoint_string', { value: s });
  }

  KS.phaseH = {
    init: function () {
      var f = (S.il2cpp && S.il2cpp.ptrs) || {};
      if (H.il2cpp_string_new !== false && f.il2cpp_string_new) {
        U.attachSafe('il2cpp_string_new', f.il2cpp_string_new, {
          onEnter: function (args) { try { emit('il2cpp_string_new', U.readCStr(args[0], maxLen)); } catch (e) {} }
        });
        KS.log.important(P, 'string_new_hooked', {});
      }
      if (f.il2cpp_string_new_len) {
        U.attachSafe('il2cpp_string_new_len', f.il2cpp_string_new_len, {
          onEnter: function (args) {
            try { var n = args[1].toInt32(); emit('il2cpp_string_new_len', args[0].readUtf8String(Math.min(n, maxLen))); } catch (e) {}
          }
        });
      }
      if (!f.il2cpp_string_new && !f.il2cpp_string_new_len) {
        KS.log.important(P, 'phase_degraded', {
          reason: 'il2cpp_string_new not resolved (encrypted exports). This is the primary endpoint-recovery hook.',
          how_to: 'Provide il2cpp_string_new RVA in offsets/offsets.json to enable runtime URL/hostname capture.'
        });
      }
      KS.log.important(P, 'phase_ready', { keywords: kws.length });
    }
  };
})();
