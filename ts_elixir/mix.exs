defmodule TsElixir.MixProject do
  use Mix.Project

  @source_url "https://github.com/tailscale/tailscale-rs"

  def project do
    [
      app: :tailscale,
      version: "0.2.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "Tailscale",
      description: "tailscale client in elixir",
      source_url: @source_url,
      homepage_url: @source_url,
      docs: docs(),
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.37.1", runtime: false},

      # dev
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:credo, "~>1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/util"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      files:
        ~w(lib .formatter.exs mix.exs README.md LICENSE native/ts_elixir/src native/ts_elixir/Cargo* native/ts_elixir/README.md),
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => "https://github.com/tailscale/tailscale-rs"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      api_reference: true,
      extras: ["README.md"],
      formatters: ["html"],
      # The :tailscale* erlang-style modules generate paths like :tailscale.html, which is invalid.
      # Exclude from ExDoc for now.
      filter_modules: ~r/Elixir\..*/,
      groups_for_modules: [
        Tcp: [
          Tailscale.Tcp,
          Tailscale.Tcp.Listener,
          Tailscale.Tcp.Stream
        ]
      ]
    ]
  end
end
