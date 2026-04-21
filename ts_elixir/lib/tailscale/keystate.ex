defmodule Tailscale.Keystate do
  @moduledoc """
  Key state for a Tailscale device.
  """

  @typedoc """
  32-byte X25519 private key.
  """
  @type private_key() :: <<_::256>>

  @typedoc """
  32-byte X25519 public key.
  """
  @type public_key() :: <<_::256>>

  @typedoc """
  Key state for a Tailscale device.
  """
  @type t() :: %__MODULE__{
          machine: private_key(),
          node: private_key(),
          disco: private_key(),
          network_lock: private_key()
        }

  defstruct [
    :machine,
    :node,
    :disco,
    :network_lock
  ]
end
