/*
 * Decryption OBSERVATION (locate where metadata becomes plaintext).
 *
 * This does NOT bypass or defeat any protection. It only watches for the moment
 * the (already in-process) metadata transitions from the HTProtect "HTPX"
 * container to the standard IL2CPP form, and dumps the buffer boundaries so a
 * researcher can understand the pipeline.
 *
 * Strategy (low-touch, detection-aware):
 *   1) Watch large malloc() allocations near the metadata size and any mmap'd
 *      metadata region (from Phase C). Poll each buffer's first 4 bytes for the
 *      plaintext IL2CPP magic 0xFAB11BAF. When it appears -> "plaintext_ready".
 *   2) OPTIONAL scoped memcpy/memmove/memset watchers, active ONLY while a
 *      metadata buffer is registered and ONLY when src/dst intersect a watched
 *      region. Heavy + detectable; disabled unless config phase D is on.
 *   3) OPTIONAL AES symbol hooks if a crypto lib exports them (HTProtect uses a
 *      custom cipher, so these usually do not resolve — logged as such).
 *
 * NOTE: This phase is OFF by default (config.phases.D_decrypt=false) because
 * global memcpy/polling is aggressive and HTProtect actively looks for it.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var M = CFG.metadata || {};
  var P = 'D';
  var PLAIN_MAGIC = (M.il2cpp_plain_magic || 'AF1BB1FA'); // little-endian on disk: AF 1B B1 FA
  var expSize = M.expected_size || 12039544;
  var tol = M.size_tolerance || (4 * 1024 * 1024);
  var watched = []; // {base,size,tag}
  var polled = new Set();

  function magicBytes() {
    // config stores the 4 magic bytes as they appear on disk (AF1BB1FA)
    return [parseInt(PLAIN_MAGIC.substr(0, 2), 16), parseInt(PLAIN_MAGIC.substr(2, 2), 16),
            parseInt(PLAIN_MAGIC.substr(4, 2), 16), parseInt(PLAIN_MAGIC.substr(6, 2), 16)];
  }

  function watch(base, size, tag) {
    if (!base || base.isNull()) return;
    var key = base.toString();
    if (polled.has(key)) return;
    polled.add(key);
    watched.push({ base: base, size: size, tag: tag });
    KS.log.important(P, 'watch_buffer', { base: key, size: size, tag: tag });
    pollForPlaintext(base, size, tag);
  }

  function pollForPlaintext(base, size, tag) {
    var want = magicBytes();
    var iv = M.poll_interval_ms || 50;
    var maxTicks = Math.floor(((M.poll_max_seconds || 45) * 1000) / iv);
    var ticks = 0;
    var timer = setInterval(function () {
      ticks++;
      try {
        var head = new Uint8Array(base.readByteArray(4));
        if (head[0] === want[0] && head[1] === want[1] && head[2] === want[2] && head[3] === want[3]) {
          clearInterval(timer);
          var dump = null;
          try { dump = base.readByteArray(Math.min(size, 256)); } catch (e) {}
          KS.log.bytes(P, 'plaintext_ready', {
            base: base.toString(), size: size, tag: tag,
            magic: PLAIN_MAGIC, note: 'IL2CPP plaintext metadata magic observed in-buffer',
            head: U.hexPreview(base, 32), bt: null
          }, dump);
        }
      } catch (e) { /* region may be freed/remapped */ }
      if (ticks >= maxTicks) { clearInterval(timer); }
    }, iv);
  }

  function hookLargeMalloc() {
    ['malloc', 'calloc', 'realloc'].forEach(function (fn) {
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) {
          if (fn === 'calloc') this.sz = args[0].toInt32() * args[1].toInt32();
          else if (fn === 'realloc') this.sz = args[1].toInt32();
          else this.sz = args[0].toInt32();
          this.big = this.sz >= (expSize - tol) && this.sz <= (expSize + tol);
        },
        onLeave: function (ret) {
          if (!this.big || ret.isNull()) return;
          KS.log.important(P, 'metadata_sized_alloc', {
            fn: fn, size: this.sz, ptr: ret.toString(),
            bt: U.backtrace(this.context, 'decrypt')
          });
          watch(ret, this.sz, 'malloc');
        }
      });
    });
  }

  function hookScopedMemops() {
    ['memcpy', 'memmove', 'memset'].forEach(function (fn) {
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) {
          if (watched.length === 0) return; // inert until a metadata buffer exists
          var dst = args[0];
          var src = (fn === 'memset') ? null : args[1];
          var n = args[2].toInt32();
          for (var i = 0; i < watched.length; i++) {
            var w = watched[i], end = w.base.add(w.size);
            var hitDst = dst.compare(w.base) >= 0 && dst.compare(end) < 0;
            var hitSrc = src && src.compare(w.base) >= 0 && src.compare(end) < 0;
            if (hitDst || hitSrc) {
              KS.log.event(P, 'memop_on_region', {
                fn: fn, n: n, dst: dst.toString(), src: src ? src.toString() : null,
                region: w.base.toString(), hit: hitDst ? 'dst' : 'src',
                src_head: src ? U.hexPreview(src, 16) : null,
                bt: U.backtrace(this.context, 'decrypt')
              });
              break;
            }
          }
        }
      });
    });
    KS.log.important(P, 'scoped_memops_armed', { note: 'active only when a metadata buffer is registered' });
  }

  function hookAES() {
    var cands = ['AES_set_decrypt_key', 'AES_decrypt', 'AES_cbc_encrypt', 'EVP_DecryptInit_ex', 'EVP_DecryptUpdate', 'CCCrypt'];
    var any = false;
    cands.forEach(function (n) {
      var p = U.exp(null, n);
      if (!p) return;
      any = true;
      U.attachSafe(n, p, {
        onEnter: function () { KS.log.event(P, 'aes_call', { fn: n, bt: U.backtrace(this.context, 'decrypt') }); }
      });
    });
    KS.log.important(P, 'aes_symbols', { found: any, note: any ? 'standard AES exports present' : 'no standard AES exports (HTProtect uses a custom cipher) — rely on plaintext_ready detector' });
  }

  KS.phaseD = {
    init: function () {
      KS.bus.on('metadata_buffer', function (d) { watch(d.base, d.size, d.source || 'bus'); });
      hookLargeMalloc();
      hookScopedMemops();
      hookAES();
      KS.log.important(P, 'phase_ready', { magic: PLAIN_MAGIC, expected_size: expSize });
    }
  };
})();
