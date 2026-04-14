# ts_packetfilter

Tailscale packet filters.

Filters are specified per-tailnet using the policy file's ACL and/or grants
features. They are downloaded to each node on connection to a control
server and when the rules or tailnet changes.
