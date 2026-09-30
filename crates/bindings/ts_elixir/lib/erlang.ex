defmodule :tailscale do
  @moduledoc """
  Erlang-friendly re-export of `Tailscale`.
  """

  defdelegate connect(options), to: Tailscale
  defdelegate connect(config_path, options), to: Tailscale
  defdelegate ipv4_addr(dev), to: Tailscale
  defdelegate ipv6_addr(dev), to: Tailscale
  defdelegate peer_by_name(dev, name), to: Tailscale
end

defmodule :tailscale_tcp do
  @moduledoc """
  Erlang-friendly re-export of `Tailscale.Tcp`.
  """

  defdelegate listen(dev, addr, port), to: Tailscale.Tcp
  defdelegate connect(dev, addr, port), to: Tailscale.Tcp
end

defmodule :tailscale_tcp_listener do
  @moduledoc """
  Erlang-friendly re-export of `Tailscale.Tcp.Listener`.
  """

  defdelegate accept(listener), to: Tailscale.Tcp.Listener
  defdelegate local_addr(listener), to: Tailscale.Tcp.Listener
end

defmodule :tailscale_tcp_stream do
  @moduledoc """
  Erlang-friendly re-export of `Tailscale.Tcp.Stream`.
  """

  defdelegate send(stream, msg), to: Tailscale.Tcp.Stream
  defdelegate send_all(stream, msg), to: Tailscale.Tcp.Stream
  defdelegate recv(stream), to: Tailscale.Tcp.Stream
  defdelegate local_addr(stream), to: Tailscale.Tcp.Stream
  defdelegate remote_addr(stream), to: Tailscale.Tcp.Stream
end

defmodule :tailscale_udp do
  @moduledoc """
  Erlang-friendly re-export of `Tailscale.Udp`.
  """

  defdelegate bind(dev, addr, port), to: Tailscale.Udp
  defdelegate send(sock, remote, port, payload), to: Tailscale.Udp
  defdelegate recv(sock), to: Tailscale.Udp
  defdelegate local_addr(sock), to: Tailscale.Udp
end
