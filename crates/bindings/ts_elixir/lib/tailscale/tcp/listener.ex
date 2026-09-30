defmodule Tailscale.Tcp.Listener do
  @moduledoc """
  Tailscale TCP listening socket functionality.
  """

  @typedoc """
  A TCP listener waiting for incoming connections.
  """
  @opaque t :: Tailscale.Native.tcp_listener()

  @spec accept(t()) :: {:ok, Tailscale.Tcp.Stream.t()} | {:error, any()}
  @doc """
  Accept an incoming connection on the socket, yielding a connected `Tailscale.Tcp.Stream`.
    
  Blocks until a connection is ready.
  """
  def accept(res) do
    Tailscale.Native.tcp_accept(res)
  end

  @doc """
  Get the local address on which this listener is bound.
  """
  @spec local_addr(t()) :: {:inet.ip_address(), :inet.port_number()}
  def local_addr(listener) do
    Tailscale.Native.tcp_listen_local_addr(listener)
  end
end
