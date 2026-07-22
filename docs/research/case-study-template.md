# Case-study template (synthetic)

Use this template to publish a **generalised**, synthetic write-up of an analysis
without exposing any target-specific data. Real, target-specific case studies stay
in a private, gitignored `research/` directory and are never committed.

> Replace every placeholder. Keep all values synthetic or clearly generalised.
> Do not include real endpoints, identifiers, class inventories, or captured
> user data.

---

## 1. Subject & authorisation

- **Class of target:** e.g. "a hardened Unity IL2CPP mobile title".
- **Authorisation basis:** e.g. "own build", "engagement scope #…", "CTF".
- **Engine / metadata version:** e.g. Unity 2022.3, IL2CPP metadata v29.

## 2. Static picture

- Native libraries of interest (generic roles: engine, scripting, protection).
- IL2CPP data layout and whether metadata is transformed on disk.
- Managed assemblies and the protocol-relevant namespaces (generalised).

## 3. Instrumentation observations

- Library load order and JNI registration surface.
- Network endpoints observed (generalise or redact).
- Notable runtime strings (categories, not values).

## 4. Protocol

- Transport & framing (cite the standard if applicable).
- Serialization format.
- Representative command taxonomy (use **synthetic** names).
- Timing characteristics (heartbeat interval class, RTT range).

## 5. Schema evidence

Summarise a few commands with per-field confidence, using synthetic field names:

| command | field | type | confidence |
|---|---|---|---|
| `method:login` | `#1` | str | Verified |
| … | … | … | … |

## 6. Knowledge-base metrics

- sessions imported, distinct commands, packet observations, classes.
- confidence distribution (Verified/Likely/Unknown counts).

## 7. Version evolution (optional)

- new/removed opcodes, changed schemas between two releases (generalised).

## 8. Limitations & unknowns

- What could not be observed and why (grade honestly).

## 9. Ethics statement

- Authorisation, coordinated disclosure, and data-handling notes.

---

For the framework's own methodology, see [methodology.md](methodology.md).
