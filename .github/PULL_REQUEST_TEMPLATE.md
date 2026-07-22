## Summary

<!-- What does this change and why? -->

## Type
- [ ] Bug fix
- [ ] Feature (observation-only)
- [ ] Docs
- [ ] Refactor / tooling

## Observation-only checklist (required)
- [ ] No `Interceptor.replace` / behaviour-altering hooks
- [ ] No `Memory.write*` / RWX patching / byte patching
- [ ] No packet injection, replay, delay, drop, or modification
- [ ] No request/traffic generation toward a target
- [ ] No automation, bots, cheats, or protection bypass
- [ ] No captured data from a real target added to the repo

## Quality
- [ ] `make check` passes (ruff + black + pytest)
- [ ] Tests added/updated
- [ ] Docs / CHANGELOG updated if needed
