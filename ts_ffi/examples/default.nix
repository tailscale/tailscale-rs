# build the examples.
#
# this doesn't use the makefile because it assumes nix has already built the lib, which is available
# as `libtailscalers`.
{
    stdenv,
    libtailscalers,
}: stdenv.mkDerivation {
    name = "ts_ffi_examples";
    version = libtailscalers.version;

    src = ./.;

    CFLAGS = "-Wall -Wextra -Werror -O2 -lm -lpthread -l:libtailscalers.a -L${libtailscalers}/lib/ -I${libtailscalers}/include/";

    buildPhase = ''
        runHook preBuild

        cc -o udp_ping_ udp_ping/*.c $CFLAGS
        cc -o tcp_echo_ tcp_echo/*.c $CFLAGS
        cc -o lookup_peer_ lookup_peer/*.c $CFLAGS

        runHook postBuild
    '';

    installPhase = ''
        runHook preInstall

        mkdir -p "$out/bin"
        cp udp_ping_ "$out/bin/udp_ping"
        cp tcp_echo_ "$out/bin/tcp_echo"
        cp lookup_peer_ "$out/bin/lookup_peer"

        runHook postInstall
    '';

    doCheck = false;
}
