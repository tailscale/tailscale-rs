# ts_peercapability

Shared definition for Tailscale peer capabilities.

## Peer capabilities vs. node capabilities

This crate defines types for _peer capabilities_, also known in the Tailscale KB as
[app capabilities]. These are properties of a given peer-to-peer connection or network traffic flow
in your tailnet which are primarily consumed by application logic: for instance, you might use an
app capability grant to label authorized traffic, and reject at the application layer (e.g. by an
HTTP 401 or 403) if an incoming request lacks the peer capability you require.

Peer capabilities are evaluated on the client primarily as outputs of packet filter rules, which are
generated according to your cap grants definitions. Note that this usage makes "packet filter" a
misnomer, as the rules are being used strictly for labeling and do not filter network traffic when
used this way. Additionally, it's worth mentioning that some Tailscale-specific peer capabilities
are negotiated over the peer API, not via packet filter rules.

This is in contrast to _node capabilities_ ([`nodeAttrs`] in the KB) which are intrinsic properties
of peer nodes as delivered in the netmap which _do not_ require an active network flow or
peer-to-peer connection to evaluate.

[app capabilities]: https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities
[`nodeAttrs`]: https://tailscale.com/docs/reference/syntax/policy-file#nodeattrs
