/*
 * Tailnet UDP demo that sends a ping message to a peer and prints incoming messages.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "tailscale.h"

#define USAGE \
    "usage: udp_ping CONFIG_PATH AUTH_TOKEN PEER_ADDR\n" \
    "  e.g. udp_ping tsrs_keys.json tskey-auth-XXX 1.2.3.4:5678"

int main(int argc, char** argv) {
    if (argc != 4) {
        puts(USAGE);
        exit(EXIT_FAILURE);
    }

    ts_init_tracing();

    struct ts_node_key_state key_state = {0};
    assert(ts_load_key_file(argv[1], false, &key_state) >= 0);

    struct ts_config config = {0};
    config.key_state = &key_state;

    const struct ts_device* dev = ts_init(
        &config,
        argv[2]
    );
    assert(dev);

    struct ts_sockaddr addr = {
        .sa_family = TS_AF_INET,
        .sa_data = {
            .sockaddr_in = {
                .sin_port = 1234,
            },
        },
    };
    assert(!ts_ipv4_addr(dev, &addr.sa_data.sockaddr_in.sin_addr));

    char* addr_str = inet_ntoa(*(struct in_addr*)&addr.sa_data.sockaddr_in.sin_addr);
    printf("bound to %s:%u\n", addr_str, 1234);

    struct ts_udp_socket* sock = ts_udp_bind(dev, &addr);
    assert(sock);

    struct ts_sockaddr peer_addr;
    assert(ts_parse_sockaddr(argv[3], &peer_addr) >= 0);

    const char* msg = "hello from c";
    int ret = ts_udp_sendto(sock, &peer_addr, (const uint8_t*)msg, strlen(msg));
    assert(ret >= 0);
    puts("sent ping, waiting for incoming");

    static uint8_t BUF[1024];

    while (1) {
        ret = ts_udp_recvfrom(sock, &peer_addr, BUF, 1024 - 1);
        assert(ret >= 0);

        BUF[ret] = 0;
        printf("received %d bytes: %s\n", ret, BUF);
    }

    return EXIT_SUCCESS;
}
