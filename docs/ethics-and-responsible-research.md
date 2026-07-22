# Ethics & responsible research

Vantage is built for **legitimate, authorised** security research,
interoperability study, and education. Using it responsibly is a condition of
using it at all.

## Authorised use

Use Vantage only on software you are permitted to analyse, for example:

- your own applications and builds;
- targets within an authorised penetration test or red-team engagement (with a
  signed scope);
- Capture-the-Flag and academic research;
- interoperability and security research where permitted by the applicable law
  and the software's terms.

Do **not** use it to gain unfair advantage in a live service, to disrupt other
users, to exfiltrate other users' data, or in violation of a service's terms or
of applicable law.

## Observation-only, by design

The framework cannot cheat, automate, inject, or bypass protections — those
capabilities are intentionally absent (see [threat-model.md](threat-model.md)).
This is a deliberate ethical stance encoded in the architecture, not a
configuration default that can be flipped.

## Responsible disclosure

If your analysis reveals a security vulnerability in a third-party application or
service:

1. Do not exploit it beyond what is necessary to demonstrate the issue.
2. Report it privately to the vendor and allow reasonable time to remediate.
3. Prefer coordinated disclosure; follow the vendor's security policy or a
   recognised framework (e.g. a 90-day timeline).
4. Never publish captured user data or working exploits.

For vulnerabilities in **Vantage itself**, see [`SECURITY.md`](../SECURITY.md).

## Handling recovered data

- Capture sessions and knowledge bases can contain sensitive identifiers. Store
  them privately; the repository gitignores `vantage_data/`, `captures/`, and
  `*.db` by default.
- Keep target-specific research (real endpoints, real class inventories) in a
  private directory, out of any public fork.

## No target is bundled

This repository ships **no** proprietary binaries, copyrighted assets, or
target-specific captured data. All examples and sample data are **synthetic** and
clearly marked as such.
