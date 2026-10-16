# End-to-end test: the tailscale-rs examples against a real headscale, using headscale's NixOS
# test kit (https://github.com/juanfont/headscale/blob/main/nix/README.md), with Go tailscaled
# peers on the other side. Needs Linux with KVM:
#
#   nix build .#e2e -L
#   nix build .#e2e.driverInteractive && ./result/bin/nixos-test-driver
{
  pkgs,
  deps,
  rustsrc,
  headscale,
}: let
  # The test-only features let the examples fetch /key over plain HTTP and accept the kit's
  # self-signed (InsecureForTests) DERP.
  examples = pkgs.craneLib.buildPackage (deps.passthru.buildDeps // {
    pname = "tailscale-e2e-examples";
    version = "dev";

    strictDeps = true;
    src = rustsrc;

    cargoArtifacts = deps;
    cargoExtraArgs = "--locked -p tailscale --examples --features axum,ts_control/insecure-keyfetch,ts_control/insecure-derp";
    # nextest already covers the tests.
    doCheck = false;
  });

  policy = acls: pkgs.writeText "policy.json" (builtins.toJSON { acls = acls; });
  allowAll = policy [ { action = "accept"; src = [ "*" ]; dst = [ "*:*" ]; } ];
  httpOnly = policy [ { action = "accept"; src = [ "peer@" ]; dst = [ "rs@:80" ]; } ];

  goPeer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = with pkgs; [ curl jq netcat-openbsd ];
  };

in pkgs.testers.runNixOSTest {
  name = "tailscale-rs-e2e";

  nodes = {
    headscale.imports = [ headscale.nixosModules.testkit ];

    # Runs the examples: userspace netstack, no tailscaled or TUN. The direct UDP socket binds a
    # random port.
    rs.networking.firewall.enable = false;

    # tailscaled without a UDP socket: all traffic with rs crosses the kit's DERP. The NixOS
    # module doesn't trust tailscale0, and rs's datagrams must get in.
    peer = {
      imports = [ goPeer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
      networking.firewall.trustedInterfaces = [ "tailscale0" ];
    };

    # Same LAN as rs, with UDP, so disco can find a direct path.
    direct.imports = [ goPeer ];
  };

  testScript = ''
    # Every command runs under pipefail: no `head`/`grep -m` cutting a producer short. Waits
    # make one attempt per second, each also capped at T seconds.
    T = 120

    def run_example(host, example, args="", key=None):
        """Start EXAMPLE on rs as systemd unit and tailnet host HOST, with its own key file."""
        auth = f"-E TS_AUTH_KEY={key}" if key else ""
        rs.succeed(
            f"systemd-run --collect --unit={host} -E NO_COLOR=1 -E TS_CONTROL_URL=http://headscale {auth}"
            f" ${examples}/bin/{example} -H {host} -c /var/lib/rs/{host}.json {args}"
        )

    def tailnet_ip(host):
        return peer.wait_until_succeeds(f"tailscale ip -4 {host}", timeout=T).strip()

    # The helpers below build shell checks for a Go peer to run.

    def http_ok(ip):
        return f"curl -fsS -m 10 http://{ip}/index.html | grep -F '<title>tailscale-rs'"

    def peer_json(host, cond):
        return f"tailscale status --json | jq -e '.Peer[] | select(.HostName == \"{host}\") | {cond}'"

    # Setup: two tailscale-rs nodes on rs (hosts "echo" and "http"), two Go peers.
    start_all()
    rs_key = headscale.succeed("hs-authkey rs").strip()
    peer_key = headscale.succeed("hs-authkey peer").strip()
    rs.wait_for_unit("multi-user.target")
    run_example("echo", "tcp_echo", key=rs_key)
    run_example("http", "axum", key=rs_key)
    peer.succeed(f"hs-join {peer_key}")
    direct.succeed(f"hs-join {peer_key}")
    echo_ip, http_ip = tailnet_ip("echo"), tailnet_ip("http")
    # `timeout`, not `nc -w`: an echo that never closes must fail.
    tcp_echo_ok = f"echo hi | timeout 10 nc -N {echo_ip} 1234 | grep -x hi"

    # The subtests run in order and share these nodes. The policy test restores allow-all.

    with subtest("auth key + home DERP"):
        # rs ignores pings over DERP, so read its home region from a Go peer's netmap.
        peer.wait_until_succeeds(peer_json("echo", '.Relay == "headscale"'), timeout=T)

    with subtest("inbound TCP over DERP"):
        peer.wait_until_succeeds(tcp_echo_ok, timeout=T)
        peer.succeed("head -c 1M /dev/urandom > /tmp/blob")
        peer.succeed(f"timeout 60 nc -N {echo_ip} 1234 < /tmp/blob | cmp - /tmp/blob")

    with subtest("HTTP via tailscale::axum"):
        peer.wait_until_succeeds(http_ok(http_ip), timeout=T)

    with subtest("outbound UDP"):
        peer_ip = peer.succeed("tailscale ip -4").strip()
        run_example("ping", "peer_ping", f"-i 0.5 -p {peer_ip}:5678", key=rs_key)
        peer.wait_until_succeeds(
            "timeout 5 nc -d -u -l 5678 > /tmp/udp || true; grep -F hello /tmp/udp", timeout=T
        )

    with subtest("direct UDP path"):
        # With the default --until-direct, a pong relayed over DERP doesn't count.
        direct.wait_until_succeeds("tailscale ping -c 1 --timeout 3s echo", timeout=T)
        direct.wait_until_succeeds(tcp_echo_ok, timeout=T)
        direct.succeed(peer_json("echo", '.CurAddr != ""'))

    with subtest("restart reuses key file"):
        rs.succeed("systemctl stop echo")
        run_example("echo", "tcp_echo")  # no auth key this time
        # Proves the same node: a re-registered one would get a new IP, and an
        # unregistered one no IP at all.
        peer.wait_until_succeeds(tcp_echo_ok, timeout=T)

    with subtest("live packet filter"):
        headscale.succeed("headscale policy set -f ${httpOnly}")
        peer.wait_until_fails(tcp_echo_ok, timeout=T)
        # :80 still passes while :1234 is dropped, so it's the filter, not an outage.
        peer.wait_until_succeeds(http_ok(http_ip), timeout=T)
        peer.fail(tcp_echo_ok)
        headscale.succeed("headscale policy set -f ${allowAll}")
        peer.wait_until_succeeds(tcp_echo_ok, timeout=T)

    with subtest("interactive login"):
        run_example("login", "axum")  # fresh key file, no auth key
        # axum logs the auth URL from Device::is_authorized; it ends in headscale's auth ID.
        auth_id = rs.wait_until_succeeds(
            "journalctl -u login -o cat | grep -oE 'hskey-authreq-[[:xdigit:]]+'", timeout=T
        ).split()[0]
        headscale.succeed(f"headscale auth register --user rs --auth-id {auth_id}")
        peer.wait_until_succeeds(http_ok(tailnet_ip("login")), timeout=T)
  '';
}
