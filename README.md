# `ash_jwt`

JWT bearer-token authentication plug for Ash apps. The escape hatch
when mTLS isn't an option (managed API gateway, serverless platform,
cloud LB that strips the cert, developer's laptop).

## Wiring

```elixir
plug AshJwt.Plug,
  signer: AshJwt.Verifier.signer(:rs256, "/etc/secrets/jwt-pub.pem"),
  validate: [
    iss: "https://issuer.example",
    aud: "soot-devices",
    tenant_id: &is_binary/1
  ]
```

A successful request lands an `AshJwt.Actor` struct on
`conn.assigns.actor`. Set `assign_as: :ash_pki_actor` to drop into a
pipeline that already assumes the `ash_pki` mTLS plug's assign — Ash
policies that read `actor.tenant_id` work either way.

## Verifier

`AshJwt.Verifier.signer/2` builds a `Joken.Signer`:

| algorithm                        | second arg                     |
|----------------------------------|--------------------------------|
| `:hs256` / `:hs384` / `:hs512`   | shared secret (binary)         |
| `:rs256` / `:rs384` / `:rs512`   | PEM string or path to PEM file |
| `:es256` / `:es384` / `:es512`   | PEM string or path to PEM file |
| `:ps256` / `:ps384` / `:ps512`   | PEM string or path to PEM file |

`AshJwt.Verifier.verify/3` is a pure function: returns `{:ok, claims}` or
`{:error, reason}`. Useful in tests and in code that needs to verify a
token outside the plug pipeline.

`validate` is a keyword list of `claim => expected` where `expected` is
a literal, a list (claim must be one of), or a unary predicate
(`&is_binary/1`).

## Failure modes

| status | error code         | when                                              |
|--------|--------------------|---------------------------------------------------|
| 401    | `missing_token`    | no `Authorization: Bearer …` header               |
| 401    | `invalid_token`    | token is structurally malformed                   |
| 401    | `bad_signature`    | signature doesn't verify against the key          |
| 401    | `expired`          | `exp` is in the past                              |
| 401    | `not_yet_valid`    | `nbf` is in the future                            |
| 403    | `claim_mismatch`   | a claim in `validate` didn't match (claim in body)|

`:on_failure` controls what happens:

- `:halt_with_401` (default) — the table above.
- `:assign_only` — assigns `:ash_jwt_error` and continues; useful for
  endpoints that allow anonymous access but want to short-circuit later.
- `{:halt_with, fn conn, reason -> conn end}` — operator-supplied
  handler.

## What this isn't

- Not an OIDC client. Token issuance is the operator's IdP.
- Not a refresh-token mechanism — verification only.
- Not a JWKS fetcher. The signer is configured statically; a JWKS-aware
  signer is a follow-up.

## Tests

```sh
mix test
```

26 tests cover `Verifier.verify/3` (happy path with literal / list /
predicate `validate` matchers; failures: bad signature, expired,
not-yet-valid, claim mismatch in three flavours, malformed input),
`Actor.from_claims/2` (standard fields, `tid` fallback for
`tenant_id`, non-integer `exp` lands as `nil`), and the plug across
init validation, every documented response code, the
`:assign_only` and `{:halt_with, fun}` failure modes, and the
`assign_as` re-routing for `ash_pki_actor` compatibility.
