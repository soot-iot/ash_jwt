defmodule AshJwt.Test.Helpers do
  @moduledoc false

  @doc "Build a fresh HS256 signer with a known secret."
  def hs_signer(secret \\ "test-secret-of-sufficient-length"),
    do: AshJwt.Verifier.signer(:hs256, secret)

  @doc "Sign a claim map into a JWT under the given signer."
  def issue(claims, signer) do
    claims = Map.put_new(claims, "exp", System.system_time(:second) + 600)
    {:ok, token, _} = Joken.encode_and_sign(claims, signer)
    token
  end
end
