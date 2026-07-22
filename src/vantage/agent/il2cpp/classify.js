/*
 * il2cpp/classify.js — score each recovered class against the Phase-4 target
 * categories and assign a role + confidence. Shared scoring model with the
 * Python side (classify_lib.py) so on-device and offline results agree.
 *
 * Confidence combines: name-keyword strength, namespace signal, and
 * trusted-assembly/namespace context (com.fpnn / BestHTTP / CenturyGame /
 * OdinSerializer / Lua*). Purely lexical over ALREADY-RECOVERED names — no
 * inference of names that were not observed.
 */
(function () {
  // category -> {strong:[...], weak:[...]}
  var CAT = {
    Network:      { strong: ['network', 'tcpclient', 'tcpconnection', 'socket', 'connection', 'clientengine', 'receiver'], weak: ['net', 'transport', 'channel'] },
    HTTP:         { strong: ['http', 'besthttp', 'webrequest', 'httprequestwork', 'httpgetwork'], weak: ['web', 'url', 'download'] },
    Request:      { strong: ['request', 'quest'], weak: ['req'] },
    Response:     { strong: ['response', 'answer'], weak: ['resp', 'reply'] },
    Gateway:      { strong: ['gateway', 'gate'], weak: [] },
    Login:        { strong: ['login', 'auth', 'signin', 'logon', 'cgsession'], weak: ['account', 'token', 'session'] },
    Session:      { strong: ['session'], weak: ['token', 'credential'] },
    Player:       { strong: ['player', 'profile'], weak: ['user', 'role', 'avatar'] },
    Battle:       { strong: ['battle', 'combat', 'fight'], weak: ['skill', 'buff'] },
    March:        { strong: ['march', 'rally', 'troop'], weak: ['army', 'squad'] },
    Alliance:     { strong: ['alliance', 'guild', 'clan'], weak: ['union'] },
    Chat:         { strong: ['chat', 'rtm', 'im', 'conversation', 'message'], weak: ['talk'] },
    Config:       { strong: ['config', 'setting', 'configreader', 'configdata'], weak: ['cfg', 'define', 'const'] },
    Version:      { strong: ['version', 'manifest', 'hotfix', 'patch', 'checkappversion', 'versionmanifest'], weak: ['update', 'upgrade'] },
    Asset:        { strong: ['asset', 'assetloader', 'assetmodule', 'resloader', 'resource'], weak: ['res', 'texture'] },
    Bundle:       { strong: ['assetbundle', 'bundle', 'assetbundlemgr'], weak: [] },
    Lua:          { strong: ['lua', 'tolua', 'luastate', 'luaclient'], weak: [] },
    Message:      { strong: ['message', 'msg', 'notify', 'notification'], weak: [] },
    Packet:       { strong: ['packet', 'pkt'], weak: [] },
    Serialize:    { strong: ['serialize', 'serializer', 'formatter', 'msgpacker'], weak: ['encode', 'pack', 'writer'] },
    Deserialize:  { strong: ['deserialize', 'unpacker', 'msgunpacker', 'reader', 'parser'], weak: ['decode', 'unpack'] }
  };

  var TRUST = [
    { re: /^com\.fpnn/i, cats: ['Network', 'Message', 'Packet', 'Serialize', 'Deserialize', 'Chat'], boost: 0.35 },
    { re: /Best\.HTTP/i, cats: ['HTTP', 'Request', 'Response', 'Network'], boost: 0.30 },
    { re: /CenturyGame\.GameFramework/i, cats: ['Asset', 'Bundle', 'Version', 'HTTP', 'Network', 'Config'], boost: 0.20 },
    { re: /OdinSerializer/i, cats: ['Serialize', 'Deserialize'], boost: 0.30 },
    { re: /^Lua|tolua/i, cats: ['Lua'], boost: 0.30 }
  ];

  // BestHTTP's bundled BouncyCastle TLS/crypto/ASN.1 plumbing — bucket separately.
  var LIB_INTERNAL = /BouncyCastle|SecureProtocol|(^|\.)Asn1(\.|$)|Bcpg|(^|\.)Pkcs|(^|\.)Tls(\.|$)|Ocsp|(^|\.)Cms(\.|$)|Crmf|(^|\.)Ess(\.|$)|(^|\.)X509|(^|\.)Pkix/i;

  function scoreOne(assembly, ns, name) {
    if (ns && LIB_INTERNAL.test(ns)) {
      return { role: 'TlsCryptoInternal', confidence: 0.15, tier: 'low',
        categories: { TlsCryptoInternal: 0.15 }, reasons: ['third-party TLS/crypto (BestHTTP/BouncyCastle)'], library_internal: true };
    }
    var hayName = (name || '').toLowerCase();
    var hayNs = (ns || '').toLowerCase();
    var ctx = (assembly || '') + '.' + (ns || '');
    var best = { role: null, score: 0, reasons: [] }, all = {};
    Object.keys(CAT).forEach(function (cat) {
      var s = 0, why = [];
      CAT[cat].strong.forEach(function (k) { if (hayName.indexOf(k) !== -1) { s += 0.6; why.push('name~' + k); } else if (hayNs.indexOf(k) !== -1) { s += 0.3; why.push('ns~' + k); } });
      CAT[cat].weak.forEach(function (k) { if (hayName.indexOf(k) !== -1) { s += 0.2; why.push('name~' + k); } });
      TRUST.forEach(function (t) { if (t.re.test(ctx) && t.cats.indexOf(cat) !== -1) { s += t.boost; why.push('trust:' + t.re.source); } });
      if (s > 0) { all[cat] = Math.min(s, 1); if (s > best.score) best = { role: cat, score: Math.min(s, 1), reasons: why }; }
    });
    return { role: best.role, confidence: Math.round(best.score * 100) / 100, tier: best.score >= 0.75 ? 'high' : (best.score >= 0.5 ? 'medium' : (best.score > 0 ? 'low' : 'none')), categories: all, reasons: best.reasons };
  }

  KS.il2cppClassify = {
    scoreOne: scoreOne,
    categories: Object.keys(CAT)
  };
})();
