defmodule Tailscale do
  @moduledoc """
  Elixir bindings for the Tailscale Rust client. 
  """

  @typedoc """
  An IPv4 address.
    
  `tailscale` is capable of interpreting either the `inet` format or a `String`.
  """
  @type ip4_addr() :: :inet.ip4_address() | String.t()

  @typedoc """
  An IPv6 address.
    
  `tailscale` is capable of interpreting either the `inet` format or a `String`.
  """
  @type ip6_addr() :: :inet.ip6_address() | String.t()

  @typedoc """
  An IP address (v4 or v6).
    
  `tailscale` is capable of interpreting either the `inet` format or a `String`.
  """
  @type ip_addr() :: ip4_addr() | ip6_addr()

  @typedoc """
  Handle to a tailscale "device", i.e. a unique tailnet-connected identity with a network address.
  See the note in `connect/2` about nomenclature for more details.
  """
  @opaque t() :: Tailscale.Native.device()

  @spec connect(String.t(), String.t() | nil) :: {:ok, t()}
  @doc """
  Open a connection to tailscale, creating a device connected to a tailnet. 

  ## Parameters
    
  - `config_path`: the path of the config/state file to load. This contains the node's cryptographic 
    keys and therefore defines the identity of this device. It will be created if it doesn't exist.
  - `auth_key`: the auth key to be used to authorize this device. You only need to supply this if
    the device state in `config_path` has not been authorized.

  ## Nomenclature (devices, peers, nodes, etc.)

  In our parlance, anything that shows up on console.tailscale.com 
  and gets a tailnet IP is known canonically as a "device", though these are also variously been 
  referred to as "nodes" or "peers". Conventionally, each of these would be a device running 
  `tailscaled`, but with the advent of `tsnet` and now `tailscale-rs` and its derivative 
  cross-language clients, a single computer can have many Tailscale connections simultaneously, 
  possibly to many different tailnets. As an attempt to capture the whole ontology of "things that 
  have a persistent identity and tailnet IP", we try to refer to them uniformly by the umbrella term
  "device".
  """
  def connect(config_path, auth_key \\ nil) do
    Tailscale.Native.connect(config_path, auth_key)
  end

  @spec ipv4_addr(t()) :: {:ok, :inet.ip4_address()} | {:error, any()}
  @doc """
  Get the current IPv4 address of this Tailscale node.
    
  Blocks until the address is available.
  """
  def ipv4_addr(dev), do: Tailscale.Native.ipv4_addr(dev)

  @spec ipv6_addr(t()) :: {:ok, :inet.ip6_address()} | {:error, any()}
  @doc """
  Get the current IPv6 address of this Tailscale node.
    
  Blocks until the address is available.

  Note that this address is in `:inet` format (16-bit segments), which may be difficult to read. 
  See `:inet.ntoa` to format to a string.
  """
  def ipv6_addr(dev), do: Tailscale.Native.ipv6_addr(dev)

  @spec peer_by_name(t(), String.t()) :: {:ok, Tailscale.NodeInfo.t() | nil} | {:error, any()}
  @doc """
  Look up a peer by name.

  Returns `{:ok, nil}` if there was no such peer. `:error` if the lookup encountered an error.
  """
  def peer_by_name(dev, name), do: Tailscale.Native.peer_by_name(dev, name)
end
