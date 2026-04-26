# `ash_jwt` — Phase 3-adjacent quality review

Reviewed against `sprawl/soot/QUALITY-REVIEW.md` at commit `a9517a4`.
Findings ordered by severity within each group.

## Gate status (before review)

```
mix deps.unlock --check-unused   ✓ (clean after `mix deps.get`)
mix deps.audit                   ✗ task not found (mix_audit not installed)
mix format --check-formatted     ✗ test/ash_jwt/verifier_test.exs dirty
mix compile --warnings-as-errors ✓
mix credo --strict               ✗ task not found
mix sobelow                      ✗ task not found
mix test                         ✓ 26 tests, 0 failures
mix dialyzer                     ✗ task not found
```

## Correctness bugs

### 1. `matches?(_, nil) -> true` silently disables a claim check
`AshJwt.Verifier.matches?/2` has the clause

```elixir
defp matches?(_, nil), do: true
```

so any entry like `validate: [aud: nil]` always passes regardless of what
the token actually says. There is no documentation of this "skip" mode
in the moduledoc, the `verify/3` docstring, or the README. The natural
operator reading of `aud: nil` is "claim must be absent / nil"; the
actual behaviour is "don't check this at all". Either honour the
literal-equality contract (`matches?(value, nil) -> is_nil(value)`) or
document the skip behaviour explicitly. Today it's a quiet way to
disable an expected guard during config refactoring.

Reference: `lib/ash_jwt/verifier.ex:115`.

### 2. List expectation can't match a multi-valued `aud` claim
`matches?(value, list) when is_list(list), do: value in list`. JWT
permits `aud` to be a list (RFC 7519 §4.1.3) and `AshJwt.Actor`'s
`@type audience` already accepts `[String.t()]`. With a token whose
`aud` is `["soot-devices", "internal"]` and a config of
`validate: [aud: ["soot-devices", "internal"]]`, the equality does a
list-membership check (`["soot-devices","internal"] in [...]`), which
is false, so the request is rejected with `claim_mismatch`. The
intended "any-of" semantics need an `Enum.any?(list, &(&1 in expected))`
branch when the claim itself is a list, or a documented note that
list-valued claims aren't supported.

Reference: `lib/ash_jwt/verifier.ex:117`, `lib/ash_jwt/actor.ex:30`.

### 3. `:invalid_token` reason is dead — Joken returns `:signature_error` for malformed input
`classify(:token_malformed) -> :invalid_token` never fires. Joken's
`Joken.Signer.verify/2` collapses every JWT-shape failure (garbage
string, wrong number of segments, bad base64) into `:signature_error`
(verified by running `Joken.verify("garbage", signer)` and
`Joken.verify("aaa.bbb.ccc", signer)` — both return
`{:error, :signature_error}`). The `AshJwt.PlugTest`
"malformed token" test even acknowledges this:
`assert ... in ["invalid_token", "bad_signature"]`. So the entire
`:invalid_token` path in `response_for/1`, the moduledoc table, and the
README failure-mode table promises a 401 the library never emits.
Either remove the `:invalid_token` reason, switch the classifier to
distinguish (e.g. inspect the token's segment count before handing to
Joken), or note the actual collapse.

References: `lib/ash_jwt/verifier.ex:84-88`, `lib/ash_jwt/plug.ex:106`,
`README.md:48`.

### 4. `signer/2` raises (not `{:error, _}`) on a bad PEM
`JOSE.JWK.from_pem(pem)` returns a `JOSE.JWK` struct on success and
`[]` (or raises) on failure depending on input shape; either way
`Joken.Signer.create/2` then raises `FunctionClauseError` /
`ArgumentError`. The plug calls `init/1` at compile time inside many
hosts — a bad PEM file at boot is a silent crash with a stack trace
that points at `Joken.Signer`, not at `AshJwt.Verifier`. Wrap the PEM
load (`File.read/1` instead of `File.read!/1`, validate the JWK is
non-empty) and either raise `ArgumentError` with a message naming the
path, or return `{:error, :bad_pem}`. The `signer/2` doctype claims a
return of `Joken.Signer.t()`, so the second option requires a contract
change — pick one.

Reference: `lib/ash_jwt/verifier.ex:39-49`.

### 5. PEM-vs-path detection misclassifies short paths and PEM strings that happen to be readable files
`if File.regular?(pem_or_path)` runs first. A PEM string is just a
binary; `File.regular?/1` will only return true if a file with that
exact name exists, so the common case is fine, but the heuristic is
fragile under operator-supplied PEM bytes that happen to start with
something filesystem-resolvable, and any string containing `\0` will
crash `File.regular?/1` with `ArgumentError`. Safer: explicitly check
`String.starts_with?(pem_or_path, "-----BEGIN")` first, then fall
back to file IO. Same guard as `JOSE.JWK.from_pem_file/1` vs
`from_pem/1` upstream.

Reference: `lib/ash_jwt/verifier.ex:40-45`.

## Resource hygiene

(No Ash resources in `ash_jwt` — this section is empty by design.)

## Test gaps

### 6. RS256 / asymmetric `signer/2` path is never tested
Every test runs through `Helpers.hs_signer/0`. The `@asymmetric` clause
of `signer/2` (PEM string vs PEM path branches, JOSE call, alg
upcase) is wholly uncovered. The README leads with the RS256 wiring
example; that example is not exercised by the suite. Add a fixture PEM
under `test/support/fixtures/` (or generate one in `setup_all` via
`X509.PrivateKey.new_rsa(2048)` after adding `:x509` as a test dep) and
assert sign/verify round-trip plus `signer(:rs256, "/no/such.pem")`
crashes with a useful message (covers Bug 4 once that's settled).

Reference: `lib/ash_jwt/verifier.ex:39-49`,
`test/ash_jwt/verifier_test.exs:83-87`.

### 7. `nil`-expected matcher behaviour not asserted (Bug 1)
No test pins the `matches?(_, nil)` shortcut in either direction. Tied
to Bug 1 — pick a behaviour and add the corresponding assertion.

### 8. List-valued `aud` claim not asserted (Bug 2)
No test issues a token whose `aud` is itself a list; only the
"expected is a list, claim is a scalar" path is covered. Tied to Bug 2.

Reference: `test/ash_jwt/verifier_test.exs:25-28`.

### 9. `:on_failure` rejection branches don't cover `:assign_only` post-token
`PlugTest` only exercises `:assign_only` against a missing-token failure
(see `test/ash_jwt/plug/plug_test.exs:116-123`). The interesting
combination — a present-but-invalid token with `:assign_only` — has no
test, and the plug's behaviour there (continues with `:ash_jwt_error`
set to `:bad_signature`, no `:actor` assigned) is the path policies
will check.

### 10. Custom `:halt_with` handler arity-error isn't tested
`init/1` takes whatever shape comes in for `on_failure`, and `call/1`
relies on `is_function(fun, 2)`. A handler with the wrong arity
(`{:halt_with, fn _ -> :nope end}`) silently falls through every
`case` clause in `handle_failure/3` and the function returns `nil`,
which Plug then crashes on. Either validate the shape in `init/1` or
add a test that documents the current behaviour.

Reference: `lib/ash_jwt/plug.ex:85-103`.

### 11. `{:joken_error, _}` and unknown-reason fallbacks not tested
`response_for/1` has two catch-all clauses (`{:joken_error, _}` and
`_`) returning 401 `invalid_token`. No test reaches them — they
provide the only protection against a Joken upgrade returning a new
reason atom. A direct test against `response_for/1` (or a test that
injects `{:joken_error, :something_new}` via a stub) keeps the
fallback honest. Tied to Bug 3 — collapsing reasons there may also
delete this fallback.

Reference: `lib/ash_jwt/plug.ex:114-115`.

### 12. `:not_yet_valid` plug-level path is never tested
`AshJwt.VerifierTest` covers `not_yet_valid` at the verifier layer,
but `AshJwt.PlugTest` only asserts `expired`. The plug's
`response_for/1` clause for `:not_yet_valid` is therefore
verifier-tested but plug-untested — the 401 + JSON shape isn't
asserted.

Reference: `lib/ash_jwt/plug.ex:109`,
`test/ash_jwt/plug/plug_test.exs:94-102`.

### 13. `parse_exp/1` clauses partially covered
`Actor.from_claims/2` testing covers the integer and the
non-integer-binary clauses, but the `nil` clause — the realistic case
where a token simply has no `exp` — isn't asserted directly. One-liner
fix.

Reference: `lib/ash_jwt/actor.ex:53-55`,
`test/ash_jwt/actor_test.exs:31-34`.

### 14. `tenant_id` precedence (`tenant_id` wins over `tid`) not asserted
A test pins the `tid` fallback when only `tid` is present. There's no
test that says "if both `tenant_id` and `tid` exist, `tenant_id`
wins". Cheap to add.

Reference: `lib/ash_jwt/actor.ex:44`,
`test/ash_jwt/actor_test.exs:26-29`.

### 15. `test_helper.exs` doesn't enable `capture_log: true`
A bare `ExUnit.start()`. The library doesn't currently log, but the
soot_telemetry / soot_contracts review settled on `capture_log: true`
as the floor for new libraries; matching that convention up front
costs nothing.

Reference: `test/test_helper.exs:1`.

## Tooling gaps

### 16. No `LICENSE` file
`package: licenses: ["MIT"]` is declared but no LICENSE file ships.
Same finding as soot_contracts.

Reference: `mix.exs:34`.

### 17. Hex package metadata incomplete
* `links: %{}` — empty map. Add at least `"GitHub" => @source_url`.
  Hex publishing requires non-empty links in practice.
* No `@source_url` module attribute, no `source_url:` in `project/0`.
* No `files:` allow-list. Defaults will pull `_build/`, fixtures,
  etc. into the package.
* No `docs:` block, no `aliases:`. Mirror
  `soot_telemetry/mix.exs:33-69`.

Reference: `mix.exs:33-35`.

### 18. `consolidate_protocols: Mix.env() != :test`
Should be `Mix.env() == :prod`. Same playbook finding as soot_core /
soot_contracts / soot_telemetry — consolidating in `:dev` slows
iteration without any benefit.

Reference: `mix.exs:13`.

### 19. `extra_applications: [:logger, :crypto, :public_key]` is redundant
`:public_key` already pulls in `:crypto`. Drop `:crypto`. The plug
also encodes JSON via `Jason`, which already lists the apps it needs.
If `JOSE.JWK.from_pem/1` ends up needing `:ssl` (it doesn't here),
add that explicitly rather than via `:crypto`.

Reference: `mix.exs:22`.

### 20. No `.tool-versions`
Pin `elixir 1.18.3-otp-27` / `erlang 27.3` to keep CI and local in
sync with the rest of the stack.

### 21. No `CHANGELOG.md`
Mirror `soot_telemetry/CHANGELOG.md`. First entry: "Initial release —
JWT bearer-token plug, verifier, actor struct".

### 22. No CI workflow
Mirror `soot_telemetry/.github/workflows/elixir.yml` — same gate
steps. Without CI a regression in `Joken`/`JOSE`/`Plug` is caught only
by whoever next runs `mix test` locally.

### 23. No lint stack
No `.credo.exs`, no `.dialyzer_ignore.exs`, no `.sobelow-conf`, no
deps for `:credo`, `:dialyxir`, `:sobelow`, `:mix_audit`, `:ex_doc`.
Five gate commands fail with "task not found" today.

### 24. `elixir: "~> 1.16"` requirement is laxer than the stack
The rest of the stack pins `1.18.3-otp-27` via `.tool-versions` and
declares `elixir: "~> 1.16"` in `mix.exs`. Matching the loose
requirement is fine; pinning `.tool-versions` is what actually
enforces it. Listed here as a reminder once `.tool-versions` lands.

Reference: `mix.exs:10`.

## Stylistic / minor

### 25. Formatter dirty
`test/ash_jwt/verifier_test.exs:48-54` — multi-line claim map literal
inside `Joken.encode_and_sign(...)` doesn't match the formatter's
preferred shape (each claim on its own line, opening `%{` on the
arg-line). `mix format` rewrites cleanly.

### 26. README "26 tests" is hand-counted
Currently true, but a hand-maintained number drifts. Drop the count
or replace with "see `mix test`". Same nit as soot_contracts.

Reference: `README.md:75`.

### 27. `Atom.to_string(alg) |> String.upcase()` repeated
Both `signer/2` clauses do `Atom.to_string(alg) |> String.upcase()`
inline. Lift to a tiny `defp alg_string/1` — one place to enforce the
contract that algorithm atoms map to the JOSE upper-case string.

Reference: `lib/ash_jwt/verifier.ex:36, 48`.

### 28. `verify/3` `validate :: keyword() | map()` typespec under-promises
The implementation iterates with `Enum.reduce_while`, which is fine
for both. But the body relies on `{name, expected}` 2-tuples coming
out of the enumeration, which is true for keyword lists and 2-arity
maps but false for any other `Enumerable` — e.g. a `MapSet` of
2-tuples technically satisfies `Enumerable`. Either narrow the spec
to `keyword()` (the only documented usage) or widen the test to pin
both keyword and map calls (currently only keyword is tested).

Reference: `lib/ash_jwt/verifier.ex:21, 102-113`.

### 29. Plug failure-mode docstring duplicates the README table
The same status / error-code table appears in `AshJwt.Plug` moduledoc,
`AshJwt` moduledoc (partially), and `README.md`. Either link the
README from the moduledoc or accept the duplication and add a comment
that they must drift together. Drift between the README's
`invalid_token` row and the actual emitter (Bug 3) is the kind of
thing this duplication makes likely.

References: `lib/ash_jwt/plug.ex:29-35`, `README.md:43-52`.

### 30. `AshJwt` moduledoc references `AshPki.Plug.MTLS.Actor`
The compatibility note compares struct shapes against
`AshPki.Plug.MTLS.Actor`. `ash_pki` is not a declared dep of
`ash_jwt` (intentionally — these are alternatives). The reference is
informational, but a reader running `mix docs` will see a dead
moduledoc link. Either drop the bare module name or convert the
sentence to plain English without the backtick.

Reference: `lib/ash_jwt.ex:36-39`.
