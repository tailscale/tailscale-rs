defmodule Tailscale.Test.Helpers do
  @auth_env_var "TS_AUTHKEY"

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

    if k == nil || k == "" do
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

    with {:ok, dev} <- Tailscale.connect(state_file, auth_key) do
      # wait for ipv4 to be available (successful control connection)
      {:ok, _ip} = Tailscale.ipv4_addr(dev)
      {:ok, ts: dev, state_file: state_file, auth_key: auth_key}
    else
      _ -> {:error, "failed to start tailscale client"}
    end
  end
end
