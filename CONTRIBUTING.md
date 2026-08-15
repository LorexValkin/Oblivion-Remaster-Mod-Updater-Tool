# Contributing

## Generalize fixes first

Compatibility fixes must be designed as reusable, fail-closed capabilities before a mod-specific exception is considered.

A reusable fix is driven by evidence such as package identity, decoded export class, serialized schema or reference role, dependency closure, and current-template equivalence. It must not depend on a mod title, download ID, author, archive name, or one hand-picked filename when the same rule can be stated structurally.

When a reusable contract is possible:

1. Give it a versioned API or adapter identifier.
2. Define the evidence it consumes and the exact mutation it permits.
3. Apply it across every content domain that satisfies that evidence.
4. Preserve authored payloads unless a class-specific schema proves a required edit.
5. Fail closed on ambiguity and verify the rebuilt output by round trip.

A one-mod rule is allowed only when no safe structural contract can express the behavior. The reason, scope, and runtime-test requirement must be documented, and the exception must not silently authorize similar inputs.

See [Fix APIs](docs/FIX-APIS.md) for the required implementation and verification workflow.
