defmodule AshJwt.PlugTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn

  alias AshJwt.Plug, as: JwtPlug
  alias AshJwt.{Actor, Test.Helpers}

  setup do
    {:ok, signer: Helpers.hs_signer()}
  end

  defp request(token, opts) do
    conn(:get, "/protected")
    |> put_req_header("authorization", "Bearer " <> token)
    |> JwtPlug.call(JwtPlug.init(opts))
  end

  describe "init/1" do
    test "raises without a signer" do
      assert_raise ArgumentError, ~r/signer/, fn ->
        JwtPlug.init([])
      end
    end

    test "fills in defaults", %{signer: signer} do
      opts = JwtPlug.init(signer: signer)
      assert opts[:assign_as] == :actor
      assert opts[:on_failure] == :halt_with_401
      assert opts[:scheme] == "Bearer"
    end
  end

  describe "happy path" do
    test "valid token assigns the actor", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "tenant_id" => "acme"}, signer)
      conn = request(token, signer: signer)

      refute conn.halted
      actor = conn.assigns[:actor]
      assert %Actor{} = actor
      assert actor.subject == "d1"
      assert actor.tenant_id == "acme"
    end

    test "assign_as routes to a different conn key", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1"}, signer)
      conn = request(token, signer: signer, assign_as: :ash_pki_actor)

      refute conn.halted
      assert %Actor{} = conn.assigns[:ash_pki_actor]
      assert conn.assigns[:actor] == nil
    end
  end

  describe "rejection branches" do
    test "no Authorization header → 401 missing_token", %{signer: signer} do
      conn =
        conn(:get, "/protected")
        |> JwtPlug.call(JwtPlug.init(signer: signer))

      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "missing_token"
    end

    test "wrong scheme → 401 missing_token", %{signer: signer} do
      conn =
        conn(:get, "/protected")
        |> put_req_header("authorization", "Basic deadbeef")
        |> JwtPlug.call(JwtPlug.init(signer: signer))

      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "missing_token"
    end

    test "malformed token → 401 bad_signature", %{signer: signer} do
      conn = request("not-a-real-token", signer: signer)
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "bad_signature"
    end

    test "wrong signing key → 401 bad_signature", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1"}, signer)
      other = AshJwt.Verifier.signer(:hs256, "different-secret-of-sufficient-length")

      conn = request(token, signer: other)
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "bad_signature"
    end

    test "expired → 401 expired", %{signer: signer} do
      token =
        Joken.encode_and_sign(%{"sub" => "d1", "exp" => System.system_time(:second) - 60}, signer)
        |> elem(1)

      conn = request(token, signer: signer)
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "expired"
    end

    test "claim mismatch → 403 claim_mismatch with the offending claim", %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1", "iss" => "wrong"}, signer)

      conn = request(token, signer: signer, validate: [iss: "right"])
      assert conn.status == 403
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "claim_mismatch"
      assert body["claim"] == "iss"
    end
  end

  describe ":on_failure modes" do
    test ":assign_only continues with ash_jwt_error set", %{signer: signer} do
      conn =
        conn(:get, "/protected")
        |> JwtPlug.call(JwtPlug.init(signer: signer, on_failure: :assign_only))

      refute conn.halted
      assert conn.assigns[:ash_jwt_error] == :missing_token
    end

    test ":assign_only with a present-but-invalid token assigns the verify reason",
         %{signer: signer} do
      token = Helpers.issue(%{"sub" => "d1"}, signer)
      other = AshJwt.Verifier.signer(:hs256, "different-secret-of-sufficient-length")

      conn =
        conn(:get, "/protected")
        |> put_req_header("authorization", "Bearer " <> token)
        |> JwtPlug.call(JwtPlug.init(signer: other, on_failure: :assign_only))

      refute conn.halted
      assert conn.assigns[:ash_jwt_error] == :bad_signature
      assert conn.assigns[:actor] == nil
    end

    test ":halt_with passes the conn + reason to a custom function", %{signer: signer} do
      handler = fn conn, reason ->
        conn
        |> put_resp_content_type("text/plain")
        |> Plug.Conn.send_resp(418, "tea: #{inspect(reason)}")
        |> Plug.Conn.halt()
      end

      conn =
        conn(:get, "/protected")
        |> JwtPlug.call(JwtPlug.init(signer: signer, on_failure: {:halt_with, handler}))

      assert conn.status == 418
      assert conn.resp_body =~ "missing_token"
    end
  end
end
