defmodule Tailscale.Util do
  @moduledoc false
  # Internal utilities.

  @doc """
  Helper to await a Rust-side-async function that responds via message passing.

  Assumes the callee `block` returns the `:async` branch of `t:Tailscale.Native.async_reply/0`. Any
  other response is returned verbatim, assumed to be an error.
  """
  defmacro await(block, timeout \\ :infinity) do
    quote do
      Task.async(fn ->
        Tailscale.Util.await_local(unquote(block), :infinity)
      end)
      |> Task.await(unquote(timeout))
    end
  end

  @doc """
  Helper to await a Rust-side-async function that responds via message passing.

  Assumes the callee `block` returns the `:async` branch of `t:Tailscale.Native.async_reply/0`. Any
  other response is returned verbatim, assumed to be an error.

  This macro (unlike `Tailscale.Util.await/2`) awaits a response message in the current process
  without spawning a `m:Task`. This may be desirable to avoid the slight overhead of spawning a new
  process, but may not be preferred if this process's mailbox is likely to be busy.
  """
  defmacro await_local(block, timeout \\ :infinity) do
    quote do
      case unquote(block) do
        {:async, ref} ->
          receive do
            {{:tailscale, ^ref}, result} -> result
          after
            unquote(timeout) ->
              {:error, :timeout}
          end

        other ->
          other
      end
      |> Tailscale.Util.normalize_result()
    end
  end

  @doc """
  Normalize an async result to a standard Elixir-shaped return.
  """
  def normalize_result({:ok, _} = result), do: normalize_tuple(result)
  def normalize_result({:nif_panic, _} = result), do: {:error, normalize_tuple(result)}
  def normalize_result({:raise, :badarg}), do: Tailscale.Native.raise_badarg()
  def normalize_result({:raise, t}), do: raise(t)
  def normalize_result(otherwise), do: otherwise

  defp normalize_tuple({a, {}}), do: a
  defp normalize_tuple(a), do: a
end
