defmodule Tailscale.Native do
  use Rustler,
    otp_app: :tailscale,
    crate: :ts_elixir

  @moduledoc false

  # The Elixir side of the Rustler bindings to `tailscale-rs`.
  #
  # The rest of this package adapts these bindings to a more Elixir-friendly module layout -- this is
  # where Rustler actually connects the Rust nifs to their Elixir names, so it's a flat module.
  #
  # Consider this module an internal implementation detail: we may break its API at our convenience
  # without a semver bump.

  @typedoc """
  A handle to a unique tailscale "identity" on a given tailnet.
  """
  @opaque device :: reference()

  @typedoc """
  A handle to a UDP socket.
  """
  @opaque udp_socket :: reference()

  @typedoc """
  A handle to a TCP listener.
  """
  @opaque tcp_listener :: reference()
  @typedoc """
  A handle to a TCP stream (connected socket).
  """
  @opaque tcp_stream :: reference()

  @typedoc """
  NIFs provided here may have asynchronous effects that would typically block and require the use of
  the DirtyIO scheduler. This is undesirable as we may have a large number of concurrent calls into
  the NIFs, which could exhaust the DirtyIO thread pool. Instead, we use message passing on the Rust
  side to send replies back into the BEAM. Functions that use this model return `async_reply`
  without blocking. The `:async` case means the reply will be sent asynchronously using a message of
  the format `{:tailscale, REF, PAYLOAD}`, where `REF` is the reference associated with the `:async`
  response, guaranteed unique per call.

  The `:error` response means that an error was encountered before dispatching the asynchronous
  call.

  The `:nif_panic` response means that the NIF panicked during execution; the second parameter is
  the reason for the panic (if given).

  `{:raise, TERM}` means `TERM` should be raised as an exception.

  `m:Tailscale.Util` has helpers for decoding messages of this form.
  """
  @type async_reply() ::
          {:async, reference()}
          | {:error, any()}
          | {:nif_panic, String.t() | {}}
          | {:raise, any()}

  defp err, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Open a new tailnet connection.

  See `t:Tailscale.options/0` for details on what options are supported.
  """
  @spec connect(%{}) :: async_reply()
  def connect(_opts), do: err()

  @doc """
  Bind a new udp socket.

  ## Parameters

  - `dev`: the `m:Tailscale` device on which to create the socket.
  - `port`: the port to which the socket should bind.
  """
  @spec udp_bind(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) ::
          async_reply()
  def udp_bind(_dev, _addr, _port), do: err()

  @doc """
  Send a packet to an address from a udp socket.

  ## Parameters

  - `sock`: the socket to send the packet from.
  - `ip`: the IP address to send the packet to.
  - `port`: the port to send the packet to.
  - `msg`: the packet to send.
  """
  @spec udp_send(udp_socket(), Tailscale.ip_addr(), :inet.port_number(), binary()) ::
          async_reply()
  def udp_send(_sock, _ip, _port, _msg), do: err()

  @doc """
  Receive an incoming UDP packet on the given socket.
  """
  @spec udp_recv(udp_socket()) ::
          async_reply()
  def udp_recv(_sock), do: err()

  @doc """
  Get the local address to which the given UDP socket is bound.
  """
  @spec udp_local_addr(udp_socket()) :: {:inet.ip_address(), :inet.port_number()}
  def udp_local_addr(_sock), do: err()

  @doc """
  Start the Rust-side tracing machinery. This prints to stdout, so may conflict with erlang's
  logging setup.
  """
  @spec start_tracing() :: :ok
  def start_tracing(), do: err()

  @doc """
  Start a TCP listener on the given device, address, and port.
  """
  @spec tcp_listen(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) ::
          async_reply()
  def tcp_listen(_dev, _addr, _port), do: err()

  @doc """
  Get the local address to which the given TCP listener is bound.
  """
  @spec tcp_listen_local_addr(tcp_listener()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_listen_local_addr(_listener), do: err()

  @doc """
  Connect to the given TCP endpoint using the given device.
  """
  @spec tcp_connect(device(), Tailscale.ip_addr(), :inet.port_number()) ::
          async_reply()
  def tcp_connect(_dev, _addr, _port), do: err()

  @doc """
  Accept an incoming TCP connection. Blocks until one is available.
  """
  @spec tcp_accept(tcp_listener()) :: async_reply()
  def tcp_accept(_listener), do: err()

  @doc """
  Send a message to the remote peer on the given tcp socket, blocking until at least one byte can be
  sent.

  Returns the number of bytes actually written to the remote.
  """
  @spec tcp_send(tcp_stream(), binary()) :: async_reply()
  def tcp_send(_stream, _msg), do: err()

  @doc """
  Receive incoming data from the tcp socket, blocking until at least one byte can be received.
  """
  @spec tcp_recv(tcp_stream()) :: async_reply()
  def tcp_recv(_stream), do: err()

  @doc """
  Get the local address to which the given TCP stream is bound.
  """
  @spec tcp_local_addr(tcp_stream()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_local_addr(_stream), do: err()

  @doc """
  Get the remote address to which the given TCP stream is connected.
  """
  @spec tcp_remote_addr(tcp_stream()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_remote_addr(_stream), do: err()

  @doc """
  Retrieve the IPv4 address for the given tailscale device.

  Blocks until the device is connected and gets its address from control.
  """
  @spec ipv4_addr(device()) :: async_reply()
  def ipv4_addr(_dev), do: err()

  @doc """
  Retrieve the IPv6 address for the given tailscale device.

  Blocks until the device is connected and gets its address from control.
  """
  @spec ipv6_addr(device()) :: async_reply()
  def ipv6_addr(_dev), do: err()

  @doc """
  Retrieve a peer by name.
  """
  @spec peer_by_name(device(), String.t()) :: async_reply()
  def peer_by_name(_dev, _name), do: err()

  @doc """
  Retrieve this node's info
  """
  @spec self_node(device()) :: async_reply()
  def self_node(_dev), do: err()

  @doc """
  Retrieve a peer by its tailnet IP.
  """
  @spec peer_by_tailnet_ip(device(), Tailscale.ip_addr()) :: async_reply()
  def peer_by_tailnet_ip(_dev, _ip), do: err()

  @doc """
  Retrieve the most narrow set of peers that accept packets for the specified IP.
  """
  @spec peers_with_route(device(), Tailscale.ip_addr()) :: async_reply()
  def peers_with_route(_dev, _ip), do: err()

  @doc """
  Load key state from the specified path, generating a new state if the file doesn't exist.
  """
  @spec load_key_file(String.t()) :: async_reply()
  def load_key_file(_path), do: err()

  @doc """
  Raise a `:badarg` exception.
  """
  @spec raise_badarg() :: nil
  def raise_badarg(), do: err()

  if @testing_nifs do
    @doc """
    DEV ONLY: trigger an async panic in the Rust code with the given message (if provided).
    """
    @spec async_panic(String.t() | nil) :: async_reply()
    def async_panic(_msg \\ nil), do: err()

    @doc """
    DEV ONLY: trigger a raised exception in the Rust code with the given message.
    """
    @spec async_raise(String.t(), boolean()) :: async_reply()
    def async_raise(_msg, _atom \\ false), do: err()

    @doc """
    DEV ONLY: trigger an asynchronous error in the Rust code with the given message.
    """
    @spec async_error(String.t(), boolean()) :: async_reply()
    def async_error(_msg, _atom \\ false), do: err()

    @doc """
    DEV ONLY: trigger an asynchronous `:badarg` in the Rust code with the given message.
    """
    @spec async_badarg() :: async_reply()
    def async_badarg(), do: err()
  end
end
