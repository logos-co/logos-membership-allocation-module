# logos-membership-allocation-module

Logos module `membership_allocation_module`: the RLN membership allocator. A funded node registers RLN memberships on chain on behalf of authenticated
clients. The client side is
[`logos-membership-allocation-client-module`](https://github.com/logos-co/logos-membership-allocation-client-module).

## Method

- `serve(args_json)`: mount `/logos/paymaster/rln-membership/1.0.0`, advertise the served
  (registry, auth type) pairs through libp2p service discovery, authenticate each request with
  the configured auth vector, and register the commitment through the registry module on one
  serialized worker. It answers a request once the registry shows the membership.

It is one service of the paymaster engine in
[`logos-membership-allocation-crates`](https://github.com/logos-co/logos-membership-allocation-crates):
the engine provides the messages, discovery, the auth gate and replay protection; this module
resolves the registry and registers the membership. The argument and reply shapes are documented
on the trait in `rust-lib/src/lib.rs`.

## Dependencies

- `libp2p_module` (declared; loaded first by the host).
- `rln_lez_module`, the registry module (declared; loaded first by the host).
- Shared crates, pinned by commit: `membership_allocation_action`, `paymaster_service`,
  `paymaster_lp`, `paymaster_wire`, `auth_vector` and `auth_vectors` from
  `logos-membership-allocation-crates`.

## Auth vectors

`authVerifiers` names the auth types the allocator accepts; without it the allocator is open.

```json
{ "peer-any": {}, "eth-allowlist": { "config": { "allowlist": ["0x…"] } } }
```

The module verifies twelve types itself, `<scheme>-<authoriser>`:

| scheme | authorisers |
|---|---|
| `eth`, `lez`, `peer` | `allowlist`, `any` |
| `logos` | `allowlist`, `any`, `pow-claim` |
| `keycard` | `allowlist`, `any`, `attestation` |

`serve` checks each entry's `config`; its keys are in `docs/auth-vectors.md` of
`logos-membership-allocation-crates`. An entry with `module` hands its type to that module
instead (the `auth_vector` verifier contract), for a vector outside this set.

## Who pays

Every registration is paid, price and fee, by the registry module's own payer: the account
`rln_lez_module wallet_status` reports. Fund that account.

## Replay protection

Replay protection is the engine's (`paymaster_service::nullifiers`): a
verifier that returns a nullifier opts its credential into the consumed-nullifier store
(`consumedNullifiersPath`). A registration whose outcome is unknown keeps the credential spent, so
one that times out and never lands spends it.

## Build and test

```sh
nix build .#lgx-portable      # the release package
nix run .#generate            # stage rust-lib/generated/ and logos-rust-sdk-src/ for cargo
cd rust-lib && cargo test && cargo clippy --all-targets -- -D warnings
```

The tests enable the `test-fake` feature of `paymaster_lp` as a dev-dependency; the
plugin build links the real `lp_*` bindings (`cargo check --lib` compiles that path).
