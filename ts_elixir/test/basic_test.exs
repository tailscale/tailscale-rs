defmodule Tailscale.Test do
  use ExUnit.Case, async: true

  describe "client connect" do
    setup [:check_net, :auth_key, :state_file]

    test "connect", %{state_file: state_file, auth_key: auth_key} do
      {:ok, dev} = Tailscale.connect(state_file, auth_key)
      IO.puts("connected!")

      {:ok, ip} = Tailscale.ipv4_addr(dev)
      IO.puts("tailnet ip: #{ip |> :inet.ntoa()}")
    end
  end

  describe "connected client" do
    setup [:connected_client]

    test "ip4", %{ts: dev} do
      {:ok, ip} = Tailscale.ipv4_addr(dev)
      assert :inet.is_ipv4_address(ip)
    end

    test "ip6", %{ts: dev} do
      {:ok, ip} = Tailscale.ipv6_addr(dev)
      assert :inet.is_ipv6_address(ip)
    end

    test "udp bind", %{ts: dev} do
      {:ok, ip} = Tailscale.ipv4_addr(dev)
      {:ok, _sock} = Tailscale.Udp.bind(dev, ip, 1234)
    end

    test "tcp listen", %{ts: dev} do
      {:ok, ip} = Tailscale.ipv4_addr(dev)
      {:ok, _sock} = Tailscale.Tcp.listen(dev, ip, 1234)
    end
  end

  defp check_net(ctx), do: Tailscale.Test.Helpers.check_net(ctx)
  defp auth_key(ctx), do: Tailscale.Test.Helpers.auth_key(ctx)
  defp state_file(ctx), do: Tailscale.Test.Helpers.state_file(ctx)
  defp connected_client(ctx), do: Tailscale.Test.Helpers.connected_client(ctx)
end
