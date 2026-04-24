defmodule Tailscale.Test.AsyncCallbacks do
  use ExUnit.Case, async: true
  require Tailscale.Util
  alias Tailscale.Native

  defmacrop await(block, local) do
    if local do
      quote do
        Tailscale.Util.await_local(unquote(block))
      end
    else
      quote do
        Tailscale.Util.await(unquote(block))
      end
    end
  end

  for local <- [true, false] do
    describe "async calls (local: #{local})" do
      for msg <- ["msg", nil] do
        test "panic (msg: #{msg})" do
          result = await(Native.async_panic(unquote(msg)), local)

          {:error, {:nif_panic, arg}} = result

          if unquote(msg) != nil do
            assert(arg == "msg")
          end
        end
      end

      for atom <- [true, false] do
        test "error (atom: #{atom})" do
          assert(
            await(Native.async_error("msg", unquote(atom)), local) ==
              {:error,
               if unquote(atom) do
                 :msg
               else
                 "msg"
               end}
          )
        end

        test("raise (atom: #{atom})") do
          assert_raise RuntimeError, fn ->
            msg =
              if unquote(atom) do
                "Elixir.RuntimeError"
              else
                "msg"
              end

            await(
              Native.async_raise(msg, unquote(atom)),
              local
            )
          end
        end
      end

      test "badarg" do
        assert_raise ArgumentError, fn ->
          await(Native.async_badarg(), local)
        end
      end
    end
  end
end
