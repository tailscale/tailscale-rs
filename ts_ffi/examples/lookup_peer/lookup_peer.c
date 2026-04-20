/*
 * Command-line utility to look up IP addresses for a peer on your tailnet.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "tailscale.h"

#define USAGE \
    "usage: lookup_peer CONFIG_PATH AUTH_TOKEN PEER_NAME\n" \
    "  e.g. lookup_peer test.json tskey-auth-XXX mynode"

int main(int argc, char** argv) {
    if (argc != 4) {
        puts(USAGE);
        exit(EXIT_FAILURE);
    }

    const struct ts_device* dev = ts_init(
        argv[1],
        argv[2]
    );
    assert(dev);

    // Wait for device to receive its IP: first netmap has been received.
    ts_in_addr_t addrv4;
    ts_in6_addr_t addrv6;
    char addr_str[INET6_ADDRSTRLEN];

    assert(!ts_ipv4(dev, &addrv4));

    if (ts_peer_ipv4_addr(dev, argv[3], &addrv4) <= 0) {
        return EXIT_FAILURE;
    }
    assert(inet_ntop(AF_INET, &addrv4, addr_str, INET6_ADDRSTRLEN));
    puts(addr_str);

    if (ts_peer_ipv6_addr(dev, argv[3], &addrv6) <= 0) {
        return EXIT_FAILURE;
    }
    assert(inet_ntop(AF_INET6, &addrv6, addr_str, INET6_ADDRSTRLEN));
    puts(addr_str);

    return EXIT_SUCCESS;
}
