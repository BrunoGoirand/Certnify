# Certnify specifications

These English specifications define the current functional behavior, storage
formats, cryptographic policies and failure boundaries of Certnify. They provide
a language-independent basis for reimplementation. There is one authoritative
chapter for each topic; the guides explain how to use the Bash/Make implementation.
No separate correction plan or historical audit is needed to interpret the rules.

## Reading order

| Document | Contract |
| --- | --- |
| [01 — Scope and domain](01-scope-and-domain.md) | Actors, identities, states and supported capabilities |
| [02 — Commands and configuration](02-commands-and-configuration.md) | Operations, defaults, precedence, selectors and FILE rules |
| [03 — Persistence and artifacts](03-persistence-and-artifacts.md) | Layout, index, serials, metadata, naming and issuer bindings |
| [04 — Cryptography and profiles](04-cryptography-and-profiles.md) | Keys, subjects, SANs, exact extensions and effective policy |
| [05 — Issuance](05-issuance.md) | Root, intermediate and leaf workflows |
| [06 — Verification and revocation](06-verification-and-revocation.md) | Trust outcomes, CRL coverage and single/bulk revocation |
| [07 — Lifecycle and migration](07-lifecycle-and-migration.md) | Directory transitions, inventories, batches and final CRL publication |
| [08 — Architecture and reliability](08-architecture-and-reliability.md) | Component boundaries, locking, commits and recovery |
| [09 — Compatibility and limitations](09-compatibility-and-limitations.md) | Import requirements, deliberate restrictions and qualification limits |
| [10 — Acceptance and traceability](10-acceptance-and-traceability.md) | Acceptance scenarios, executable tests and implementation mapping |
| [Guides](guides/README.md) | English/French usage and recovery procedures |

## How to use this specification

Preserve observable successful workflows, certificate semantics, issuer identity,
serial uniqueness, retained revocation history and explicit failure outcomes.
Paths and OpenSSL text files describe the supported interoperability format;
a new implementation may use a different internal store with an explicit import
and export mapping. Bash commands are adapters, not a required implementation
language. Suggested internal interfaces are labeled as such, not public APIs.

Limits are part of the contract: a durable command fence and checked persistence
barriers support verified resumption or manual crash reconciliation. Automatic
repair, distributed locking and hardware-independent power-loss guarantees are
not promised; real storage power-cut behavior remains to be qualified.
Validation results qualify only the platform and scenarios listed in chapter 10.
A future implementation must not turn a partial failure into an implicit retry or
assume an untested behavior is guaranteed. Profile fragments in `../profiles/`
and regression fixtures supply executable policy and acceptance evidence.
