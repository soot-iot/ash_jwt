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

    test "malformed token", %{signer: signer} do
      assert {:error, _} = Verifier.verify("not-a-jwt", signer)
    end
  end

  describe "signer/2" do
    test "hs256 with a binary secret returns a Joken.Signer" do
      assert %Joken.Signer{} = AshJwt.Verifier.signer(:hs256, "abc-of-sufficient-length")
    end
  end
end
