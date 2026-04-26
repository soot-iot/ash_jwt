defmodule AshJwt.Verifier do
  @moduledoc """
  Pure JWT verification helpers, layered over Joken/JOSE.

  `signer/2` builds a `Joken.Signer` from a configured key. Symmetric
  algorithms (`:hs256`/`:hs384`/`:hs512`) take a binary secret;
  asymmetric algorithms (`:rs256`/`:es256`/etc.) take a PEM file path
  or PEM string for the **public** key.

  `verify/3` decodes a token, verifies the signature, and validates
  every claim in `validate`. Returns `{:ok, claims}` or
  `{:error, reason}`. `reason` is one of:

    * `:bad_signature` — signature did not verify, or the token is
      structurally malformed (Joken collapses both into the same
      `:signature_error` reason at the wire layer).
    * `:expired` — `exp` is in the past.
    * `:not_yet_valid` — `nbf` is in the future.
    * `{:claim_mismatch, name}` — a configured claim didn't match.
  """

  @type validate :: keyword() | map()
  @type verify_result :: {:ok, map()} | {:error, term()}

  @symmetric ~w(hs256 hs384 hs512)a
  @asymmetric ~w(rs256 rs384 rs512 es256 es384 es512 ps256 ps384 ps512)a

  @doc """
  Build a `Joken.Signer`.

  For symmetric algorithms (`:hs256`/`:hs384`/`:hs512`) the second
  argument is the operator-supplied secret. For asymmetric algorithms
  it is either a PEM string or a path to a PEM file.
  """
  @spec signer(atom(), String.t()) :: Joken.Signer.t()
  def signer(alg, secret_or_pem) when alg in @symmetric and is_binary(secret_or_pem) do
    Joken.Signer.create(Atom.to_string(alg) |> String.upcase(), secret_or_pem)
  end

  def signer(alg, pem_or_path) when alg in @asymmetric and is_binary(pem_or_path) do
    pem = load_pem(pem_or_path)

    case JOSE.JWK.from_pem(pem) do
      %JOSE.JWK{} = jwk ->
        Joken.Signer.create(Atom.to_string(alg) |> String.upcase(), jwk)

      _ ->
        raise ArgumentError,
              "AshJwt.Verifier.signer/2: could not parse a PEM-encoded JWK from #{inspect(pem_or_path)}"
    end
  end

  defp load_pem(pem_or_path) do
    if File.regular?(pem_or_path) do
      case File.read(pem_or_path) do
        {:ok, contents} ->
          contents

        {:error, reason} ->
          raise ArgumentError,
                "AshJwt.Verifier.signer/2: could not read PEM file #{inspect(pem_or_path)}: #{:file.format_error(reason)}"
      end
    else
      pem_or_path
    end
  end

  @doc """
  Verify `token` against `signer` and `validate`.

  `validate` is a keyword list / map of `claim => expected`. The
  expected may be:

    * a literal value — equality
    * a function `(value -> boolean)` — runs against the claim
    * a list — claim must be one of these

  Built-in `exp` and `nbf` are checked automatically; you don't need
  to put them in `validate`.
  """
  @spec verify(String.t(), Joken.Signer.t(), validate()) :: verify_result()
  def verify(token, %Joken.Signer{} = signer, validate \\ []) do
    with {:ok, claims} <- decode_and_verify(token, signer),
         :ok <- check_exp(claims),
         :ok <- check_nbf(claims),
         :ok <- check_validate(claims, validate) do
      {:ok, claims}
    end
  end

  defp decode_and_verify(token, signer) do
    case Joken.verify(token, signer) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, reason} ->
        {:error, classify(reason)}
    end
  end

  defp classify(:signature_error), do: :bad_signature
  defp classify(:invalid_signature), do: :bad_signature
  defp classify(:token_malformed), do: :bad_signature
  defp classify({:bad_signature, _}), do: :bad_signature
  defp classify(other), do: {:joken_error, other}

  defp check_exp(%{"exp" => exp}) when is_integer(exp) do
    if exp < System.system_time(:second), do: {:error, :expired}, else: :ok
  end

  defp check_exp(_), do: :ok

  defp check_nbf(%{"nbf" => nbf}) when is_integer(nbf) do
    if nbf > System.system_time(:second), do: {:error, :not_yet_valid}, else: :ok
  end

  defp check_nbf(_), do: :ok

  defp check_validate(claims, validate) do
    Enum.reduce_while(validate, :ok, fn {name, expected}, :ok ->
      key = to_string(name)
      value = Map.get(claims, key)

      if matches?(value, expected) do
        {:cont, :ok}
      else
        {:halt, {:error, {:claim_mismatch, name}}}
      end
    end)
  end

  defp matches?(value, nil), do: is_nil(value)
  defp matches?(value, fun) when is_function(fun, 1), do: !!fun.(value)

  defp matches?(value, list) when is_list(list) and is_list(value),
    do: Enum.any?(value, &(&1 in list))

  defp matches?(value, list) when is_list(list), do: value in list
  defp matches?(value, expected), do: value == expected
end
