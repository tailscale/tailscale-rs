defmodule Tailscale.Test do
  use ExUnit.Case, async: true

  import Tailscale.Test.Helpers,
    only: [check_net: 1, auth_key: 1, state_file: 1, connected_client: 1]

  @net_skip !Tailscale.Test.Helpers.enable_net_tests()

  describe "client connect" do
    setup [:check_net, :auth_key, :state_file]

    @tag skip: @net_skip
    test "connect", %{state_file: state_file, auth_key: auth_key} do
      {:ok, dev} = Tailscale.connect(state_file, auth_key: auth_key)
      IO.puts("connected!")

      {:ok, ip} = Tailscale.ipv4_addr(dev)
      IO.puts("tailnet ip: #{ip |> :inet.ntoa()}")
    end
  end

  describe "connected client" do
    setup [:connected_client]

    @tag skip: @net_skip
    test "ip4", %{ipv4: ip} do
      assert :inet.is_ipv4_address(ip)
    end

    @tag skip: @net_skip
    test "ip6", %{ipv6: ip} do
      assert :inet.is_ipv6_address(ip)
    end

    @tag skip: @net_skip
    test "udp bind", %{ts: dev, ipv4: ip} do
      {:ok, _sock} = Tailscale.Udp.bind(dev, ip, 1234)
    end

    @tag skip: @net_skip
    test "tcp listen", %{ts: dev, ipv4: ip} do
      {:ok, _sock} = Tailscale.Tcp.listen(dev, ip, 1234)
    end
  end
end
