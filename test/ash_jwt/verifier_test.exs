defmodule AshJwt.VerifierTest do
  use ExUnit.Case, async: true

  alias AshJwt.Test.Helpers
  alias AshJwt.Verifier

  setup do
    {:ok, signer: Helpers.hs_signer()}
  end

  describe "verify/3 success" do
    test "valid token", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "device-001"}, signer)
      assert {:ok, claims} = Verifier.verify(token, signer)
      assert claims["sub"] == "device-001"
    end

    test "checks every claim in `validate`", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "tenant_id" => "acme", "iss" => "x"}, signer)

      assert {:ok, _} =
               Verifier.verify(token, signer, iss: "x", tenant_id: &is_binary/1)
    end

    test "list expectation matches when value is in the list", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "aud" => "soot-devices"}, signer)
      assert {:ok, _} = Verifier.verify(token, signer, aud: ["soot-devices", "other"])
    end

    test "list-valued claim matches when any audience is expected", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "aud" => ["soot-devices", "internal"]}, signer)

      assert {:ok, _} =
               Verifier.verify(token, signer, aud: ["soot-devices", "internal"])

      assert {:ok, _} =
               Verifier.verify(token, signer, aud: ["internal"])

      assert {:error, {:claim_mismatch, :aud}} =
               Verifier.verify(token, signer, aud: ["other"])
    end

    test "nil expectation matches only when the claim is absent", %{signer: signer} do
      absent = Helpers.issue(%{"sub" => "d1"}, signer)
      assert {:ok, _} = Verifier.verify(absent, signer, tenant_id: nil)

      present = Helpers.issue(%{"sub" => "d1", "tenant_id" => "acme"}, signer)

      assert {:error, {:claim_mismatch, :tenant_id}} =
               Verifier.verify(present, signer, tenant_id: nil)
    end
  end

  describe "verify/3 failures" do
    test "bad signature", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1"}, signer)
      other = AshJwt.Verifier.signer(:hs256, "wrong-secret-of-sufficient-length")

      assert {:error, :bad_signature} = Verifier.verify(token, other)
    end

    test "expired token", %{signer: signer} do
      token =
        Joken.encode_and_sign(%{"sub" => "d1", "exp" => System.system_time(:second) - 60}, signer)
        |> elem(1)

      assert {:error, :expired} = Verifier.verify(token, signer)
    end

    test "not yet valid", %{signer: signer} do
      token =
        Joken.encode_and_sign(
          %{
            "sub" => "d1",
            "nbf" => System.system_time(:second) + 600,
            "exp" => System.system_time(:second) + 1200
          },
          signer
        )
        |> elem(1)

      assert {:error, :not_yet_valid} = Verifier.verify(token, signer)
    end

    test "claim mismatch (literal)", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "iss" => "wrong"}, signer)
      assert {:error, {:claim_mismatch, :iss}} = Verifier.verify(token, signer, iss: "right")
    end

    test "claim mismatch (predicate)", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "tenant_id" => 42}, signer)

      assert {:error, {:claim_mismatch, :tenant_id}} =
               Verifier.verify(token, signer, tenant_id: &is_binary/1)
    end

    test "claim mismatch (list)", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "aud" => "stranger"}, signer)

      assert {:error, {:claim_mismatch, :aud}} =
               Verifier.verify(token, signer, aud: ["soot-devices", "internal"])
    end

    test "malformed token collapses to bad_signature", %{signer: signer} do
      assert {:error, :bad_signature} = Verifier.verify("not-a-jwt", signer)
      assert {:error, :bad_signature} = Verifier.verify("aaa.bbb.ccc", signer)
    end
  end

  describe "signer/2" do
    test "hs256 with a binary secret returns a Joken.Signer" do
      assert %Joken.Signer{} = AshJwt.Verifier.signer(:hs256, "abc-of-sufficient-length")
    end
  end

  describe "signer/2 asymmetric (RS256)" do
    setup do
      private = X509.PrivateKey.new_rsa(2048)
      public = X509.PublicKey.derive(private)
      private_pem = X509.PrivateKey.to_pem(private)
      public_pem = X509.PublicKey.to_pem(public)

      tmp = Path.join(System.tmp_dir!(), "ash_jwt_pub_#{System.unique_integer([:positive])}.pem")
      File.write!(tmp, public_pem)
      on_exit(fn -> File.rm(tmp) end)

      {:ok,
       private_signer: signer_for_jwk(:rs256, private_pem),
       public_pem: public_pem,
       public_pem_path: tmp}
    end

    test "PEM string round-trips a verified token", %{
      private_signer: priv_signer,
      public_pem: public_pem
    } do
      pub_signer = AshJwt.Verifier.signer(:rs256, public_pem)
      token = Helpers.issue(%{"sub" => "device-rsa"}, priv_signer)

      assert {:ok, claims} = Verifier.verify(token, pub_signer)
      assert claims["sub"] == "device-rsa"
    end

    test "PEM file path round-trips a verified token", %{
      private_signer: priv_signer,
      public_pem_path: path
    } do
      pub_signer = AshJwt.Verifier.signer(:rs256, path)
      token = Helpers.issue(%{"sub" => "device-rsa-path"}, priv_signer)

      assert {:ok, claims} = Verifier.verify(token, pub_signer)
      assert claims["sub"] == "device-rsa-path"
    end

    test "missing PEM file raises ArgumentError that names the path" do
      path = "/tmp/no-such-ash-jwt-pem-#{System.unique_integer([:positive])}.pem"

      assert_raise ArgumentError, ~r/#{Regex.escape(path)}/, fn ->
        AshJwt.Verifier.signer(:rs256, path)
      end
    end

    test "garbage PEM string raises ArgumentError" do
      assert_raise ArgumentError, ~r/parse/, fn ->
        AshJwt.Verifier.signer(:rs256, "-----BEGIN garbage not actually a key-----")
      end
    end
  end

  defp signer_for_jwk(alg, private_pem) do
    Joken.Signer.create(alg |> Atom.to_string() |> String.upcase(), %{"pem" => private_pem})
  end
end
