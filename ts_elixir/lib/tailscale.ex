defmodule Tailscale do
  @moduledoc """
  Elixir bindings for the Tailscale Rust client.

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

  @typedoc """
  Options for connecting to Tailscale:

  - `auth_key`: the auth key to use to authorize this device. You only need to supply this if the
    device's keys aren't authorized.
  - `keys`: the `m:Tailscale.Keystate` to use to connect. This defines the device identity.
  - `hostname`: the hostname this device will request. If omitted, uses the hostname the OS reports.
  - `tags`: tags the device will request.
  - `control_url`: the url of the control server to use.
  """
  @type options :: [
          auth_key: String.t(),
          keys: Tailscale.Keystate.t(),
          control_url: String.t(),
          hostname: String.t(),
          tags: [String.t()]
        ]

  @spec connect(String.t(), options()) :: {:ok, t()} | {:error, any()}
  @doc """
  Open a connection to tailscale, creating a device connected to a tailnet. Loads key state from
  the given path, creating it if it doesn't exist.

  See `t:options/0` for details on available options.
  """
  def connect(key_file_path, options) when is_binary(key_file_path) do
    case Tailscale.Native.load_key_file(key_file_path) do
      {:ok, keys} ->
        Keyword.put(options, :keys, keys) |> connect()

      err ->
        err
    end
  end

  @spec connect(options() | String.t()) :: {:ok, t()} | {:error, any()}
  @doc """
  Open a connection to Tailscale, creating a device connected to a tailnet. If the argument is a
  `m:String`, this is equivalent to `connect/2` with an empty option list.

  See `t:options/0` for details on available options. You may want to call `connect/2` for an easier
  way to load key state from a file.
  """
  def connect(options \\ [])

  def connect(options) when is_list(options),
    do: :proplists.to_map(options) |> Tailscale.Native.connect()

  def connect(key_file_path) when is_binary(key_file_path), do: connect(key_file_path, [])

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

  @spec self_node(t()) :: {:ok, Tailscale.NodeInfo.t()} | {:error, any()}
  @doc """
  Get this node's `m:Tailscale.NodeInfo`.
  """
  defdelegate self_node(dev), to: Tailscale.Native
end
