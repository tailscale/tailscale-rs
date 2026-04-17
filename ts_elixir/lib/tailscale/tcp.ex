defmodule Tailscale.Tcp do
  @moduledoc """
  Functionality to create tailscale TCP sockets.

  See `Tailscale.Tcp.Listener` and `Tailscale.Tcp.Stream` for listen and established sockets,
  respectively.
  """

  @doc """
  Create a TCP listener on the specified port.

  ## Parameters

  - `dev`: the tailscale device.
  - `addr`: the address to listen on. You can either pass an address or `:ip4`/`:ip6` to bind to the
            tailscale device's respective tailnet address.
  - `port`: the port to listen on.
  """
  @spec listen(Tailscale.t(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) ::
          {:ok, Tailscale.Tcp.Listener.t()} | {:error, any()}
  def listen(dev, addr, port) do
    Tailscale.Native.tcp_listen(dev, addr, port)
  end

  @doc """
  Open a TCP connection to the specified address and port.
  """
  @spec connect(Tailscale.t(), Tailscale.ip_addr(), :inet.port_number()) ::
          {:ok, Tailscale.Tcp.Stream.t()} | {:error, any()}
  def connect(dev, addr, port) do
    Tailscale.Native.tcp_connect(dev, addr, port)
  end
end
