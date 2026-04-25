defmodule AshJwt.ActorTest do
  use ExUnit.Case, async: true

  alias AshJwt.Actor

  test "from_claims pulls standard fields" do
    claims = %{
      "sub" => "device-001",
      "tenant_id" => "acme",
      "iss" => "issuer",
      "aud" => "soot-devices",
      "exp" => 1_900_000_000
    }

    actor = Actor.from_claims(claims, "the-token")

    assert actor.subject == "device-001"
    assert actor.tenant_id == "acme"
    assert actor.issuer == "issuer"
    assert actor.audience == "soot-devices"
    assert %DateTime{} = actor.expires_at
    assert actor.token == "the-token"
    assert actor.claims == claims
  end

  test "tenant_id falls back to `tid` when missing" do
    actor = Actor.from_claims(%{"sub" => "d1", "tid" => "acme"}, "tok")
    assert actor.tenant_id == "acme"
  end

  test "non-integer exp leaves expires_at nil" do
    actor = Actor.from_claims(%{"sub" => "d1", "exp" => "not-a-unix"}, "tok")
    assert is_nil(actor.expires_at)
  end
end
