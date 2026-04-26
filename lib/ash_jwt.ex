defmodule AshJwt do
  @moduledoc """
  JWT bearer-token authentication for Ash apps.

  An alternative to mTLS for environments where the operator cannot
  terminate mTLS — typically a serverless platform, a managed-API
  gateway, or a developer's laptop. The wire surface is the standard
  `Authorization: Bearer <token>` header.

  ## Surface

    * `AshJwt.Plug` — the plug. Verifies the token's signature against a
      configured key, validates the standard `exp`/`nbf`/`iss`/`aud`
      claims (plus operator-specified custom claims), and assigns an
      `AshJwt.Actor` struct to `conn.assigns`.
    * `AshJwt.Actor` — what policies see. Carries the verified `subject`,
      `tenant_id`, `claims`, and the raw decoded JWT.
    * `AshJwt.Verifier` — pure verification functions wrapping `Joken`.
      Useful in tests and in code that needs to verify a token outside
      the plug pipeline.

  ## Wiring

      plug AshJwt.Plug,
        signer: AshJwt.Verifier.signer(:rs256, "key.pem"),
        validate: [
          iss: "https://issuer.example",
          aud: "soot-devices",
          tenant_id: &is_binary/1
        ]

  ## Compatibility with the mTLS plug

  Set `assign_as: :ash_pki_actor` in plug opts to write into the same
  conn assign that an mTLS plug like `ash_pki`'s would use. Downstream
  plugs and Ash policies continue to work unchanged. The actor struct
  shape is different from the mTLS actor; policies that pattern match
  on a specific struct must be updated, but policies that read
  `actor.tenant_id` work either way.
  """
end
