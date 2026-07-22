# IL2CPP metadata recovery

Modules: [`agent/il2cpp/`](../../src/vantage/agent/il2cpp/) (runtime) and
[`vantage.metadata`](../../src/vantage/metadata/) (classification).

## The core idea

Unity's IL2CPP backend compiles C# to native code and ships type information in
`global-metadata.dat`. On hardened builds this file may be transformed on disk
and the `libil2cpp` export **names** stripped or scrambled — but at runtime the
VM must load the type system into memory to run at all. Vantage recovers the type
system by calling the runtime's **own read-only enumeration API** against that
already-in-memory metadata:

```
il2cpp_domain_get()
  → domain_get_assemblies → assembly_get_image → image_get_class
      → class_get_name / _get_namespace / _get_methods
          → method_get_name / _get_param_count / _get_return_type
          → MethodInfo.methodPointer  → RVA
```

This is observation, not decryption: the framework reads the *product* of the
runtime's own initialisation. It does **not** decrypt `global-metadata.dat`, and
it does **not** extract keys.

## Locating the API without export names

[`api_locator.js`](../../src/vantage/agent/il2cpp/api_locator.js) resolves the
API through a layered strategy, each result **behaviourally validated** before
use (walk a tiny slice and sanity-check counts/names):

| Layer | Technique | Reliability |
|---|---|---|
| L1 | named exports | works on stock builds |
| L2 | researcher-supplied RVAs (`offsets.json`) | **most reliable on hardened builds** |
| L3 | export-index auto-map + behavioural validation | best-effort; opt-in (calls unknown addresses) |
| L4 | CodeRegistration/MetadataRegistration structural scan | locates registration structs / bootstraps offsets |

L2 offsets must be obtained from a static analysis of a **decrypted** dump that
the researcher is authorised to produce. Vantage does not produce that dump and
does not defeat any protection.

## Classification

[`metadata/classifier.py`](../../src/vantage/metadata/classifier.py) (mirrored in
[`agent/il2cpp/classify.js`](../../src/vantage/agent/il2cpp/classify.js)) scores
recovered class names against protocol-relevant categories (Network, Login,
Session, Version, Asset, Serialize, …) using name/namespace keywords and
trusted-namespace boosts, with third-party TLS/crypto library internals bucketed
out. [`metadata/inventory.py`](../../src/vantage/metadata/inventory.py) ranks a
whole inventory by confidence.

The JS and Python classifiers are kept in lockstep (identical results), verified
by [`tests/test_versions_and_search.py`](../../tests/test_versions_and_search.py).

## Outputs

- `types.json` — Assembly → Namespace → Class → Method tree with RVAs
- `networking_classes.ranked.json` — classified classes with confidence + reasons

Both feed the knowledge base, where class↔command relationships are formed.

## Failure modes

- **API not locatable** (no offsets, probe disabled) — recovery reports the
  locator remedy and any registration-scan candidates, then stops. It never
  blind-calls unknown addresses unless explicitly opted in.
- **Partial metadata** — traversal records what it can and marks the rest
  `Unknown`.
