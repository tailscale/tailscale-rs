defmodule Tailscale.Test.Helpers do
  @moduledoc """
  Common Tailscale test helper functions.
  """

  @auth_env_var "TS_RS_TEST_AUTHKEY"
  @net_enable_env_var "TS_RS_TEST_NET"

  def enable_net_tests() do
    truthy?(System.get_env(@net_enable_env_var))
  end

  def check_net(_ctx) do
    case :gen_tcp.connect(~c"controlplane.tailscale.com", 443, [:binary, active: false]) do
      {:ok, _} ->
        :ok

      _ ->
        {:error, "couldn't tcp connect"}
    end
  end

  def auth_key(_ctx) do
    k = System.get_env(@auth_env_var)

    if empty?(k) do
      {:error, "#{@auth_env_var} not set"}
    else
      {:ok, auth_key: k}
    end
  end

  def state_file(_ctx) do
    state_file = "#{System.tmp_dir!()}/tsrs_ex_test/state_#{Enum.random(0..65535)}.json"
    File.rm(state_file)

    ExUnit.Callbacks.on_exit(fn -> File.rm(state_file) end)

    {:ok, state_file: state_file}
  end

  def connected_client(ctx) do
    :ok = check_net(ctx)
    {:ok, auth_key: auth_key} = auth_key(ctx)
    {:ok, state_file: state_file} = state_file(ctx)

    case Tailscale.connect(state_file, auth_key: auth_key) do
      {:ok, dev} ->
        # wait for ipv4 to be available (successful control connection)
        {:ok, _ip} = Tailscale.ipv4_addr(dev)
        {:ok, ts: dev, state_file: state_file, auth_key: auth_key}

      _ ->
        {:error, "failed to start tailscale client"}
    end
  end

  defp empty?(nil), do: true
  defp empty?(""), do: true
  defp empty?(_), do: false

  defp truthy?(nil), do: false
  defp truthy?(x), do: x |> String.downcase() |> _truthy?

  defp _truthy?("1"), do: true
  defp _truthy?("true"), do: true
  defp _truthy?("yes"), do: true
  defp _truthy?("on"), do: true
  defp _truthy?(_), do: false
end
