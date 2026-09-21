defmodule Tailscale.NodeInfo do
  @moduledoc """
  Module just to provide the struct definition.

  The actual struct is produced on the Rust side.
  """

  @type t :: %__MODULE__{}

  defstruct [
    :id,
    :hostname,
    :stable_id,
    :derp_region,
    :node_key,
    :disco_key,
    :machine_key,
    underlay_addresses: [],
    tags: [],
    tailnet: nil,
    tailnet_addresses: []
  ]
end
