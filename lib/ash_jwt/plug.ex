defmodule AshJwt.Plug do
  @moduledoc """
  Plug that authenticates requests via a JWT bearer token.

  ## Wiring

      plug AshJwt.Plug,
        signer: AshJwt.Verifier.signer(:rs256, "/etc/secrets/jwt-pub.pem"),
        validate: [
          iss: "https://issuer.example",
          aud: "soot-devices",
          tenant_id: &is_binary/1
        ]

  ## Options

    * `:signer` — required. A `Joken.Signer` (build with
      `AshJwt.Verifier.signer/2`).
    * `:validate` — keyword list of claim → expected; see
      `AshJwt.Verifier.verify/3` for the matcher rules.
    * `:assign_as` — atom under `conn.assigns`. Defaults to `:actor`.
      Set to `:ash_pki_actor` to drop into a pipeline that already
      assumes the `AshPki.Plug.MTLS` assign.
    * `:on_failure` — `:halt_with_401` (default), `:assign_only`, or
      `{:halt_with, fn conn, reason -> conn end}`.
    * `:scheme` — auth header scheme. Defaults to `"Bearer"`.

  ## Failure modes

    * `401` with `error: "missing_token"` when there's no Authorization header.
    * `401` with `error: "invalid_token"` when the token is malformed.
    * `401` with `error: "bad_signature"` when the signature is wrong.
    * `401` with `error: "expired"` / `"not_yet_valid"` for time-claim issues.
    * `403` with `error: "claim_mismatch"` and `claim:` field when a
      configured claim didn't match.
  """

  @behaviour Plug
  import Plug.Conn

  alias AshJwt.{Actor, Verifier}

  @impl true
  def init(opts) do
    if Keyword.get(opts, :signer) == nil do
      raise ArgumentError, "AshJwt.Plug requires `:signer` (build with AshJwt.Verifier.signer/2)"
    end

    Keyword.merge(
      [
        validate: [],
        assign_as: :actor,
        on_failure: :halt_with_401,
        scheme: "Bearer"
      ],
      opts
    )
  end

  @impl true
  def call(conn, opts) do
    with {:ok, token} <- read_token(conn, opts[:scheme]),
         {:ok, claims} <- Verifier.verify(token, opts[:signer], opts[:validate]) do
      actor = Actor.from_claims(claims, token)
      assign(conn, opts[:assign_as], actor)
    else
      {:error, reason} -> handle_failure(conn, reason, opts)
    end
  end

  defp read_token(conn, scheme) do
    case get_req_header(conn, "authorization") do
      [header | _] -> parse_header(header, scheme)
      _ -> {:error, :missing_token}
    end
  end

  defp parse_header(header, scheme) do
    case String.split(header, " ", parts: 2) do
      [^scheme, token] when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end

  defp handle_failure(conn, reason, opts) do
    case opts[:on_failure] do
      :assign_only ->
        assign(conn, :ash_jwt_error, reason)

      {:halt_with, fun} when is_function(fun, 2) ->
        fun.(conn, reason)

      :halt_with_401 ->
        {status, code, extras} = response_for(reason)

        body = Jason.encode!(Map.merge(%{error: code}, extras))

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(status, body)
        |> halt()
    end
  end

  defp response_for(:missing_token), do: {401, "missing_token", %{}}
  defp response_for(:invalid_token), do: {401, "invalid_token", %{}}
  defp response_for(:bad_signature), do: {401, "bad_signature", %{}}
  defp response_for(:expired), do: {401, "expired", %{}}
  defp response_for(:not_yet_valid), do: {401, "not_yet_valid", %{}}

  defp response_for({:claim_mismatch, name}),
    do: {403, "claim_mismatch", %{claim: to_string(name)}}

  defp response_for({:joken_error, _}), do: {401, "invalid_token", %{}}
  defp response_for(_), do: {401, "invalid_token", %{}}
end
