"""
Tailscale API.
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Any, Awaitable, final


@final
class Device:
    """
    Tailscale client.
    """

    def ipv4_addr(self, /) -> "Awaitable[IPv4Address]":
        """
        Get the device's IPv4 tailnet address.
        """

    def ipv6_addr(self, /) -> "Awaitable[IPv6Address]":
        """
        Get the device's IPv6 tailnet address.
        """

    def peer_by_name(self, /, name: "str") -> "Awaitable[dict[str, Any]]":
        """
        Look up info about a peer by its name.
        
        `name` may be an unqualified hostname or a fully-qualified name.
        """

    def peer_by_tailnet_ip(self, /, ip: "IPv4Address | IPv6Address | str") -> "Awaitable[dict[str, Any]]":
        """
        Look up a peer by its tailnet IP address.
        """

    def peers_with_route(self, /, ip: "IPv4Address | IPv6Address | str") -> "Awaitable[list[dict[str, Any]]]":
        """
        Look up peer(s) with the most specific route match for the given address.
        
        If more than one peer has the same route covering the same address, more than one
        result may be returned.
        """

    def self_node(self, /) -> "Awaitable[dict[str, Any]]":
        """
        Get this device's node info.
        """

    def tcp_connect(self, /, addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[TcpStream]":
        """
        Create a new TCP connection to the given `addr`.
        
        `addr` must be given as (host, port). Presently, `host` must be an IP.
        """

    def tcp_listen(self, /, addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[TcpListener]":
        """
        Bind a new TCP listen socket on the given `addr` and `port`.
        
        `addr` must be given as (host, port). Presently, `host` must be an IP.
        """

    def tcp_proxy_server(self, /, listen_addr: "tuple[IPv4Address | IPv6Address | str, int]",
                         target_addr: "tuple[IPv4Address | IPv6Address | str, int]",
                         remote_buf_len: "int | None" = None,
                         target_buf_len: "int | None" = None) -> "Awaitable[TcpProxyServer]":
        """
        Proxies a remote TCP stream to a target TCP stream.
        
        # Warning
        `target_addr` may contain any valid IPv4/IPv6 address. If `target_addr` references anything
        other than a tailnet peer, data sent between the proxy and the target will no longer be
        encrypted, and will be sent in plaintext. This includes `target_addr`s such as localhost
        (127.0.0.0/8, etc.), a private IP address (10.0.0.0/8, fd00::/8, etc.), or a public IP
        address (1.2.3.4, etc.). Consider the risks of proxying a tailnet peer with a target remote
        before using this method.
        
        # Details
        Listens on the given `listen_addr` for an incoming TCP connection from a remote tailnet
        peer. Once the remote stream is established, connects to the given `target_addr` to
        establish the target stream, then proxies bytes between the two streams until one stream
        closes, or the task is canceled.
        
        Each direction of the proxy (remote-to-target and target-to-remote) uses a buffer to hold
        bytes being proxied. The size of each of these buffers can be tuned with `remote_buf_len`
        and `target_buf_len`, respectively. By default, these buffers are 8KiB in size.
        """

    def udp_bind(self, /, addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[UdpSocket]":
        """
        Bind a new UDP socket on the given `addr`.
        
        `addr` must be given as (host, port). Presently, `host` must be an IP.
        """


@final
class Keystate:
    """
    Tailscale keys.
    """

    def __new__(cls, /, machine: "bytes | None" = None, node: "bytes | None" = None,
                network_lock: "bytes | None" = None) -> Keystate: ...

    def __repr__(self, /) -> str: ...

    @property
    def machine(self, /) -> bytes:
        """
        Machine key.
        """

    @property
    def network_lock(self, /) -> bytes:
        """
        Network lock key.
        """

    @property
    def node(self, /) -> bytes:
        """
        Node (device) key.
        """


@final
class TcpListener:
    """
    A TCP listen socket.
    """

    def __repr__(self, /) -> str: ...

    def accept(self, /) -> "Awaitable[TcpStream]":
        """
        Accept a new incoming connection.
        
        Blocks indefinitely until a connection is ready to be accepted.
        """

    def local_addr(self, /) -> "tuple[IPv4Address | IPv6Address, int]":
        """
        Get the local endpoint this TCP listener is listening on.
        """


@final
class TcpStream:
    """
    An established TCP stream.
    """

    def __repr__(self, /) -> str: ...

    def fileno(self, /) -> int:
        """
        Report the file descriptor number for this TCP stream.
        
        As this is a tailscale userspace device, there is no file descriptor, so this always
        raises an `OsError`.
        """

    def isatty(self, /) -> bool:
        """
        Report whether this is a TTY.
        
        Always returns `False`.
        """

    def local_addr(self, /) -> "tuple[IPv4Address | IPv6Address, int]":
        """
        Get the local endpoint this socket is bound to.
        """

    def readable(self, /) -> bool:
        """
        Report whether the stream is writable.
        
        Always returns `True`.
        """

    def recv(self, /) -> "Awaitable[bytes]":
        """
        Receive bytes from the stream.
        
        Always returns at least one byte if not an error.
        """

    def remote_addr(self, /) -> "tuple[IPv4Address | IPv6Address, int]":
        """
        Get the remote endpoint this socket is connected to.
        """

    def seekable(self, /) -> bool:
        """
        Report whether the stream is writable.
        
        Always returns `False`.
        """

    def send(self, /, msg: "bytes") -> "Awaitable[int]":
        """
        Send bytes to the stream, returning the number of bytes transmitted.
        
        Always sends at least one byte if not an error.
        """

    def tell(self, /) -> int:
        """
        Report the current position.
        
        TCP streams don't support seeking, so this always returns `0`.
        """

    def writable(self, /) -> bool:
        """
        Report whether the stream is writable.
        
        Always returns `True`.
        """


@final
class UdpSocket:
    """
    A tailscale UDP socket.
    """

    def __repr__(self, /) -> str: ...

    def local_addr(self, /) -> "tuple[IPv4Address | IPv6Address, int]":
        """
        Get the local endpoint this socket is bound to.
        """

    def recvfrom(self, /) -> "Awaitable[tuple[bytes, tuple[IPv4Address | IPv6Address | str, int]]]":
        """
        Receive a datagram from the socket.
        
        Returns a tuple `(bytes, address)`, e.g. `(b"hello", ("127.0.0.1", 1234))`.
        """

    def sendto(self, /, addr: "tuple[IPv4Address | IPv6Address | str, int]", msg: "bytes") -> "Awaitable[None]":
        """
        Send a datagram to the given address.
        
        The address argument is currently expected to adopt the 2-tuple form (host, port),
        where host is strictly an IP address -- DNS lookup is not yet supported.
        """


def connect(key_file_path: "str | None" = None, /, auth_key: "str | None" = None, *,
            control_server_url: "str | None" = None, hostname: "str | None" = None, tags: "list[str] | None" = None,
            keys: "Keystate | None" = None) -> "Awaitable[Device]":
    """
    Connect to tailscale using the specified parameters.
    """
