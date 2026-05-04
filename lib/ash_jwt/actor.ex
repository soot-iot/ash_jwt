defmodule AshJwt.Actor do
  @moduledoc """
  The verified JWT identity exposed to Ash policies.

  Pulled from a successfully verified token by `AshJwt.Plug`:

    * `subject`   — the `sub` claim. Typically the device serial or user id.
    * `tenant_id` — convention: pulled from `tenant_id` (or `tid`) claim.
    * `audience`  — the `aud` claim, single value or list.
    * `issuer`    — the `iss` claim.
    * `expires_at` — DateTime parsed from `exp`.
    * `claims`    — every claim from the verified payload (raw map).
    * `token`     — the original encoded JWT (kept for upstream services
      that need to forward it).

  ## Missing-claim semantics

  Every field on the actor (except `claims` and `token`) defaults to
  `nil` if the corresponding claim is absent from the token. JWT
  semantics make "claim absent" and "claim present with JSON null"
  indistinguishable after parsing, so we do not try to surface that
  distinction.

  Apps that *require* a tenant id should enforce it at the policy
  layer (e.g. `policy actor_attribute_equals(:tenant_id, ...)` or
  `forbid_if attribute_equals(:tenant_id, nil)`) rather than expecting
  `from_claims/2` to fail.
  """

  defstruct [
    :subject,
    :tenant_id,
    :audience,
    :issuer,
    :expires_at,
    :claims,
    :token
  ]

  @type t :: %__MODULE__{
          subject: String.t() | nil,
          tenant_id: String.t() | nil,
          audience: String.t() | [String.t()] | nil,
          issuer: String.t() | nil,
          expires_at: DateTime.t() | nil,
          claims: map(),
          token: String.t()
        }

  @doc """
  Build an `Actor` from a verified claim map and the raw token.
  """
  @spec from_claims(map(), String.t()) :: t()
  def from_claims(claims, token) when is_map(claims) and is_binary(token) do
    %__MODULE__{
      subject: claims["sub"],
      tenant_id: claims["tenant_id"] || claims["tid"],
      audience: claims["aud"],
      issuer: claims["iss"],
      expires_at: parse_exp(claims["exp"]),
      claims: claims,
      token: token
    }
  end

  defp parse_exp(nil), do: nil
  defp parse_exp(unix) when is_integer(unix), do: DateTime.from_unix!(unix)
  defp parse_exp(_), do: nil
end
