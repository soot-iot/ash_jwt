# Changelog

All notable changes to `ash_jwt` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to semantic versioning.

## [Unreleased]

### Added
- Direct test coverage for `Verifier.signer/2` asymmetric (RS256) path
  including PEM-string and PEM-file-path round-trips.
- Coverage for `Verifier.matches?/2` with `nil` expected values and
  list-valued claim values.
- `Plug.response_for/1` is `@doc false` and exercised by tests for the
  `{:joken_error, _}` and unknown-reason fallbacks.
- `Plug.init/1` validates `:on_failure` shape and rejects an invalid
  handler arity at boot.
- `:assign_only` plug coverage for present-but-invalid tokens.
- `:not_yet_valid` plug-level response shape.
- `Actor.from_claims/2` coverage for missing `exp` and the
  `tenant_id`-wins-over-`tid` precedence.

### Changed
- `Verifier.matches?/2`: `nil` expected now requires the claim to be
  absent / nil instead of silently disabling the check.
- `Verifier.matches?/2`: list-valued claims (per RFC 7519) now match
  if any audience appears in the expected list.
- `Verifier.signer/2`: asymmetric path raises `ArgumentError` naming
  the path on a bad PEM instead of crashing inside Joken.
- `Verifier.signer/2`: PEM detection by `"-----BEGIN"` prefix instead
  of `File.regular?/1` (avoids the `\0` `ArgumentError` and ambiguous
  filesystem-state heuristic).
- `Verifier.signer/2`: asymmetric path hands a `%{"pem" => pem}`
  key_config to Joken — passing a `JOSE.JWK` struct directly never
  worked.
- Dead `:invalid_token` reason removed; malformed JWTs collapse to
  `:bad_signature` as the wire layer already does.

## [0.1.0] - 2026-04-26

### Added
- Initial release: JWT bearer-token plug, verifier helpers, and
  `Actor` struct exposed to Ash policies.
