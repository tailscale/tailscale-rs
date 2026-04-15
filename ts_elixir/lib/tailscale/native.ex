defmodule Tailscale.Native do
  use Rustler,
      otp_app: :tailscale,
      crate: :ts_elixir
      
  @moduledoc """
  The Elixir side of the Rustler bindings to `tailscale-rs`.
  
  The rest of this package adapts these bindings to a more Elixir-friendly module layout -- this is
  where Rustler actually connects the Rust nifs to their Elixir names, so it's a flat module.
  """

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

  defp err, do: :erlang.nif_error(:nif_not_loaded)
  
  @doc """
  Open a new tailnet connection.
  
  ## Parameters
  
  - `config_path`: the path to the state file to load (created if it doesn't exist)
  - `auth_key`: the auth key to use to authorize this device (may be `nil` if the device is already
  authorized)
  """
  @spec connect(String.t(), String.t() | nil) :: {:ok, device()} | {:error, any()}
  def connect(_config_path, _auth_key), do: err() 
  
  @doc """
  Bind a new udp socket.

  ## Parameters

  - `dev`: the `m:Tailscale` device on which to create the socket.
  - `port`: the port to which the socket should bind.
  """
  @spec udp_bind(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) :: {:ok, udp_socket()} | {:error, any()}
  def udp_bind(_dev, _addr, _port), do: err()

  @doc """
  Send a packet to an address from a udp socket.

  ## Parameters

  - `sock`: the socket to send the packet from.
  - `ip`: the IP address to send the packet to. Currently this must be a string.
  - `port`: the port to send the packet to.
  - `msg`: the packet to send.
  """
  @spec udp_send(udp_socket(), Tailscale.ip_addr(), :inet.port_number(), binary()) :: :ok | {:error, any()}
  def udp_send(_sock, _ip, _port, _msg), do: err()

  @doc """
  Receive an incoming UDP packet on the given socket.
  """
  @spec udp_recv(udp_socket()) :: {:ok, :inet.ip_address(), :inet.port_number(), binary()} | {:error, any()}
  def udp_recv(_sock), do: err()

  @doc """
  Get the local address to which the given UDP socket is bound.
  """
  @spec udp_local_addr(udp_socket()) :: {:inet.ip_address(), :inet.port_number()}
  def udp_local_addr(_sock), do: err()

  @doc """
  Start a TCP listener on the given device, address, and port.
  """
  @spec tcp_listen(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) :: {:ok, tcp_listener()} | {:error, any()}
  def tcp_listen(_dev, _addr, _port), do: err()

  @doc """
  Get the local address to which the given TCP listener is bound.
  """
  @spec tcp_listen_local_addr(tcp_listener()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_listen_local_addr(_listener), do: err()

  @doc """
  Connect to the given TCP endpoint using the given device.
  """
  @spec tcp_connect(device(), Tailscale.ip_addr(), :inet.port_number()) :: {:ok, tcp_stream()} | {:error, any()}
  def tcp_connect(_dev, _addr, _port), do: err()
  
  @doc """
  Accept an incoming TCP connection. Blocks until one is available.
  """
  @spec tcp_accept(tcp_listener()) :: {:ok, tcp_stream()} | {:error, any()}
  def tcp_accept(_listener), do: err()
  
  @doc """
  Send a message to the remote peer on the given tcp socket, blocking until at least one byte can be
  sent.
  
  Returns the number of bytes actually written to the remote.
  """
  @spec tcp_send(tcp_stream(), binary()) :: {:ok, integer()} | {:error, any()}
  def tcp_send(_stream, _msg), do: err()
  
  @doc """
  Receive incoming data from the tcp socket, blocking until at least one byte can be received.
  """
  @spec tcp_recv(tcp_stream()) :: {:ok, binary()} | {:error, any()}
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
  @spec ipv4_addr(device()) :: {:ok, :inet.ip4_address()} | {:error, any()}
  def ipv4_addr(_dev), do: err()
  
  @doc """
  Retrieve the IPv6 address for the given tailscale device.
  
  Blocks until the device is connected and gets its address from control.
  """
  @spec ipv6_addr(device()) :: {:ok, :inet.ip6_address()} | {:error, any()}
  def ipv6_addr(_dev), do: err()

  @doc """
  Retrieve a peer by name.
  """
  @spec peer_by_name(device(), String.t()) :: {:ok, %{} | nil} | {:error, any()}
  def peer_by_name(_dev, _name), do: err()
end
