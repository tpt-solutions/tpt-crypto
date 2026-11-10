# tpt-crypto-cli

Command-line front end to the tpt-crypto recipes. Binary name: `tpt-crypto`.

```text
tpt-crypto selftest
tpt-crypto hash <in|->
tpt-crypto random <bytes>
tpt-crypto sign-keygen <seed-out> <pub-out>
tpt-crypto sign <seed-file> <in|-> <sig-out>
tpt-crypto verify <pub-file> <in|-> <sig-file>
tpt-crypto seal-keygen <key-out>
tpt-crypto seal <key-file> <in|-> <out>
tpt-crypto open <key-file> <in|-> <out>
```

Key and signature files are hex text. Output files are created new and never
overwritten. On Unix, secret key files are created with mode `0600`; on other
platforms the default permissions apply.

Exit codes: `0` success, `1` a check failed (`verify` mismatch, `open`
authentication failure, self-test failure), `2` usage or I/O error.

The `seal` format is the `easy::seal` wire format: a random 24-byte nonce, the
ciphertext, then a 16-byte tag. No associated data is used by this CLI.

Scope: no key-agreement, no hybrid signatures, no PEM/DER import or export.
Those need a design decision about file formats before they go in here.

## License

MIT OR Apache-2.0
