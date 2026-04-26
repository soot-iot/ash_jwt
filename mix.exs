defmodule AshJwt.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/lawik/ash_jwt"

  def project do
    [
      app: :ash_jwt,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :public_key]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    "JWT bearer-token authentication plug for Ash apps; alternative to mTLS."
  end

  defp package do
    [
      licenses: ["MIT"],
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end

  defp aliases do
    [
      format: "format --migrate",
      credo: "credo --strict"
    ]
  end

  defp deps do
    [
      {:ash, "~> 3.24"},
      {:joken, "~> 2.6"},
      {:jose, "~> 1.11"},
      {:plug, "~> 1.19"},
      {:jason, "~> 1.4"},

      # Test
      {:x509, "~> 0.8", only: :test},

      # Dev / test
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false}
    ]
  end
end
