import Config

config :tailscale,
  testing_nifs: false,
  profile: :debug

import_config "#{config_env()}.exs"
