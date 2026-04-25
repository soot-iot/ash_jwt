defmodule AshJwt.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :ash_jwt,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),
      description: description(),
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    "JWT bearer-token authentication plug for Ash apps; alternative to mTLS."
  end

  defp package do
    [licenses: ["MIT"], links: %{}]
  end

  defp deps do
    [
      {:ash, "~> 3.24"},
      {:joken, "~> 2.6"},
      {:jose, "~> 1.11"},
      {:plug, "~> 1.19"},
      {:jason, "~> 1.4"}
    ]
  end
end
