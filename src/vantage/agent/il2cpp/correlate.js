/*
 * il2cpp/correlate.js — correlate recovered classes/methods with runtime strings
 * already observed by Phase H (il2cpp_string_new) and endpoints/hosts from
 * Phase E. Raises confidence when a class's name/namespace tokens co-occur with
 * observed endpoint strings or when its methods were seen via runtime_invoke.
 *
 * Observation-only bookkeeping over data the agent already collected.
 */
(function () {
  var P = 'B4';
  var observedStrings = [];   // from Phase H
  var invokedMethods = new Set(); // from Phase B runtime_invoke
  var endpointHosts = new Set();  // from Phase E dns/connect

  function tokenize(s) { return (s || '').toLowerCase().split(/[^a-z0-9]+/).filter(function (t) { return t.length >= 4; }); }

  function correlate(rec, cls) {
    var boosts = [], extra = 0;
    var tokens = new Set(tokenize(cls.name).concat(tokenize(cls.ns)));
    // string co-occurrence
    for (var i = 0; i < observedStrings.length && boosts.length < 4; i++) {
      var st = observedStrings[i].toLowerCase();
      var hit = false;
      tokens.forEach(function (t) { if (t.length >= 5 && st.indexOf(t) !== -1) hit = true; });
      if (hit) { boosts.push({ type: 'phaseH_string', value: observedStrings[i].slice(0, 80) }); extra += 0.1; }
    }
    // method invoked at runtime
    if (cls.methods) {
      for (var j = 0; j < cls.methods.length; j++) {
        var mn = cls.methods[j].name;
        if (mn && invokedMethods.has(mn)) { boosts.push({ type: 'phaseB_invoke', value: mn }); extra += 0.15; break; }
      }
    }
    return { extra: Math.min(extra, 0.4), evidence: boosts };
  }

  KS.il2cppCorrelate = {
    init: function () {
      KS.bus.on('endpoint_string', function (d) { if (d && d.value) observedStrings.push(d.value); });
      KS.bus.on('managed_class', function () {}); // ensure bus exists
      // Phase H emits 'string' via KS.log only; also capture endpoint_string bus.
      // Phase B invoked methods:
      KS.bus.on('icall', function (d) { if (d && d.name) { var mm = d.name.split('::').pop(); if (mm) invokedMethods.add(mm); } });
    },
    note: function (s) { if (s) observedStrings.push(s); },
    correlate: correlate,
    stats: function () { return { strings: observedStrings.length, invoked: invokedMethods.size }; }
  };
})();
