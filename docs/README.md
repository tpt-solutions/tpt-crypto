# tpt-crypto documentation

Guides for choosing and using the primitives in this workspace.

| Guide | Read it when |
| --- | --- |
| [Which primitive should I use?](which-primitive.md) | You have a task and need the right algorithm or recipe. |
| [Feature flags](feature-flags.md) | You are picking facade features, or building for `no_std`, WASM or an embedded target. |
| [Constant-time guarantees](constant-time.md) | You need to know what is checked, what is not, and what the claims rest on. |
| [Migrating from other libraries](migration.md) | You are moving code from `ring`, RustCrypto or `aws-lc-rs`. |

## Status

tpt-crypto is **not audited** and has not been released. The API may change before
0.1.0. See [`SECURITY.md`](../SECURITY.md) for the threat model and the disclosure
process, and [`README.md`](../README.md) for the crate layout.

Use the one-call recipes in `tpt_crypto::easy` (`feature = "classical"` +
`"os-rng"`) when they cover your need. They pick the parameters for you.
