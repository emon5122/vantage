/*
 * Metadata loading.
 * Observe how global-metadata.dat (HTPX-encrypted on this target) is opened,
 * read, and mapped. Hooks: open/openat/fopen, AAssetManager_open, read/pread,
 * mmap. Records filename, size, destination pointer, and call stack.
 *
 * Feeds Phase D via KS.bus 'metadata_buffer' so the decryption detector knows
 * which region/buffer to watch. Read-only.
 */
(function () {
  var U = KS.utils, S = KS.state, CFG = (globalThis.KS_CONFIG || {});
  var M = CFG.metadata || {};
  var names = (M.filenames || ['global-metadata.dat']);
  var contains = (M.name_contains || ['metadata', '.dat']);
  var P = 'C';

  function isInteresting(path) {
    if (!path) return false;
    var base = path.split('/').pop();
    if (names.indexOf(base) !== -1) return true;
    var low = path.toLowerCase();
    return contains.some(function (c) { return low.indexOf(c.toLowerCase()) !== -1; });
  }

  function hookOpenFamily() {
    [['open', 0], ['openat', 1]].forEach(function (pair) {
      var fn = pair[0], pathIdx = pair[1];
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) { this.path = U.readCStr(args[pathIdx], 512); this.interesting = isInteresting(this.path); },
        onLeave: function (ret) {
          if (!this.interesting) return;
          var fd = ret.toInt32();
          if (fd >= 0) S.interestFds.add(fd);
          KS.log.important(P, 'open', { fn: fn, path: this.path, fd: fd, bt: U.backtrace(this.context, 'metadata') });
        }
      });
    });

    var fopen = U.exp(null, 'fopen');
    if (fopen) U.attachSafe('fopen', fopen, {
      onEnter: function (args) { this.path = U.readCStr(args[0], 512); this.interesting = isInteresting(this.path); },
      onLeave: function (ret) {
        if (!this.interesting) return;
        KS.log.important(P, 'fopen', { path: this.path, FILE: ret.toString(), bt: U.backtrace(this.context, 'metadata') });
      }
    });
  }

  function hookAAsset() {
    var p = U.exp('libandroid.so', 'AAssetManager_open') || U.exp(null, 'AAssetManager_open');
    if (!p) { KS.log.event(P, 'aassetmanager_absent', {}); return; }
    U.attachSafe('AAssetManager_open', p, {
      onEnter: function (args) { this.path = U.readCStr(args[1], 512); this.interesting = isInteresting(this.path); },
      onLeave: function (ret) {
        if (!ret.isNull())
          KS.log.event(P, 'AAssetManager_open', { path: this.path, asset: ret.toString(), interesting: !!this.interesting },
            { important: !!this.interesting });
      }
    });
    // AAsset_read / AAsset_getBuffer reveal in-APK asset reads (Unity uses these)
    var getBuf = U.exp('libandroid.so', 'AAsset_getBuffer');
    if (getBuf) U.attachSafe('AAsset_getBuffer', getBuf, {
      onLeave: function (ret) { /* pointer to mapped asset; low value unless correlated, kept quiet */ }
    });
  }

  function hookReads() {
    [['read', false], ['pread', true], ['pread64', true]].forEach(function (pair) {
      var fn = pair[0], hasOff = pair[1];
      var p = U.exp(null, fn);
      if (!p) return;
      U.attachSafe(fn, p, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
          this.interesting = S.interestFds.has(this.fd);
          this.buf = args[1];
          this.want = args[2].toInt32 ? args[2].toInt32() : args[2].toUInt32();
          this.off = hasOff ? args[3] : null;
        },
        onLeave: function (ret) {
          if (!this.interesting) return;
          var n = ret.toInt32();
          KS.log.important(P, 'read', {
            fn: fn, fd: this.fd, requested: this.want, got: n,
            dest: this.buf.toString(), offset: this.off ? this.off.toString() : null,
            head: U.hexPreview(this.buf, Math.min(n, 32)),
            bt: U.backtrace(this.context, 'metadata')
          });
        }
      });
    });
  }

  function hookMmap() {
    var p = U.exp(null, 'mmap') || U.exp(null, 'mmap64');
    if (!p) return;
    U.attachSafe('mmap', p, {
      onEnter: function (args) {
        this.len = args[1].toInt32 ? args[1].toUInt32() : parseInt(args[1].toString());
        this.prot = args[2].toInt32();
        this.flags = args[3].toInt32();
        this.fd = args[4].toInt32();
        this.off = args[5];
        this.interesting = S.interestFds.has(this.fd);
      },
      onLeave: function (ret) {
        if (!this.interesting) return;
        var addr = ret;
        KS.log.important(P, 'mmap', {
          addr: addr.toString(), len: this.len, prot: this.prot, flags: this.flags,
          fd: this.fd, offset: this.off.toString(),
          head: U.hexPreview(addr, 16),
          bt: U.backtrace(this.context, 'metadata')
        });
        S.metadataRegions.push({ base: addr, size: this.len, tag: 'mmap_metadata' });
        KS.bus.emit('metadata_buffer', { base: addr, size: this.len, source: 'mmap', fd: this.fd });
      }
    });
  }

  KS.phaseC = {
    init: function () {
      hookOpenFamily();
      hookAAsset();
      hookReads();
      hookMmap();
      KS.log.important(P, 'phase_ready', { watching: names });
    }
  };
})();
