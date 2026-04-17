defmodule Tailscale.Udp do
  @moduledoc """
  Tailscale UDP sockets.
  """

  @typedoc """
  A handle to a tailscale UDP socket.
  """
  @opaque t() :: Tailscale.Native.udp_socket()

  @spec bind(Tailscale.t(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) :: {:ok, t()} | {:error, any()}
  @doc """
  Bind a UDP socket on the specified port.

  ## Parameters

  - `dev`: the tailscale device on which to bind a socket.
  - `addr`: the address to bind to. Passing `:ip4` or `:ip6` will cause the socket to bind to the
            tailscale node's respective tailnet ip.
  - `port`: the port number to bind.
  """
  def bind(dev, addr, port) do
    Tailscale.Native.udp_bind(dev, addr, port)
  end

  @spec send(t(), Tailscale.ip_addr(), :inet.port_number(), binary()) :: :ok | {:error, any()}
  @doc """
  Send a packet to a specified remote address.

  ## Parameters

  - `sock`: the socket to send on
  - `remote`: the host to deliver the packet to. DNS is not yet supported: this must be an IP
     address for now.
  - `port`: the port on the remote host the packet should be delivered to.
  - `payload`: the message payload.
  """
  def send(sock, remote, port, payload) do
    Tailscale.Native.udp_send(sock, remote, port, payload)
  end

  @spec recv(t()) :: {:ok, Tailscale.ip_addr(), :inet.port_number(), binary()} | {:error, any()}
  @doc """
  Receive a packet from the socket, blocking until one is ready.
  """
  def recv(sock) do
    Tailscale.Native.udp_recv(sock)
  end

  @doc """
  Get the local address on which this UDP socket is bound.
  """
  @spec local_addr(t()) :: {:inet.ip_address(), :inet.port_number()}
  def local_addr(sock) do
    Tailscale.Native.udp_local_addr(sock)
  end
end
