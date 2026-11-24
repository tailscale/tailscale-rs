# ts_nodecapability

Shared definition for the Tailscale node capabilities.

## Node capabilities vs. peer capabilities

This crate defines types for _node capabilities_, also known in the ACL file as [`nodeAttrs`]. These
are intrinsic properties of a given Tailscale node as evaluated by the control server and delivered
in the netmap. They can be inspected by various client logic without needing an active connection to
the target node, since they just live as fields on the `ts_control::Node` struct.

Node capabilities also participate in packet filtering as _inputs_ -- the control server expresses
certain network packet filter rules by requiring that the source traffic comes from a node with a
particular node capability.

This is by contrast to _peer_ capabilities, which are also known as [app capabilities] in the
Tailscale KB. These are evaluated by the client as properties of a peer-to-peer connection or
network traffic flow, and are used by application logic. They can be assigned by packet filters as
outputs but cannot participate in network-layer packet filtering as inputs.

[`nodeAttrs`]: https://tailscale.com/docs/reference/syntax/policy-file#nodeattrs
[app capabilities]: https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities
