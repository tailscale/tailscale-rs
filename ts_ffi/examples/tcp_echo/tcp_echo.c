/*
 * Tailnet-bound TCP echo server.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef WIN32
#include <Winsock2.h>
#define PTHREAD_FMT "[%llu] "
#else
#include <arpa/inet.h>
#define PTHREAD_FMT "[%lu]"
#endif

#include "tailscale.h"

#define USAGE \
    "usage: tcp_echo CONFIG_PATH AUTH_TOKEN\n" \
    "  e.g. tcp_echo tsrs_keys.json tskey-auth-XXX"

static void* run_conn_echo(void* arg) {
    uint8_t* buf = malloc(1024);
    ts_tcp_stream* stream = arg;
    pthread_t id = pthread_self();

    struct ts_sockaddr remote_addr = ts_tcp_remote_addr(stream);
    struct ts_sockaddr_in remote_addr_in = remote_addr.sa_data.sockaddr_in;

    char* addr_str = inet_ntoa(*(struct in_addr*)&remote_addr_in.sin_addr);

    printf(PTHREAD_FMT "accept from %s:%u\n", id, addr_str, remote_addr_in.sin_port);

    while (1) {
        int ret = ts_tcp_recv(stream, buf, 1024 - 1);
        if (ret == 0) {
            printf(PTHREAD_FMT "hang up\n", id);
            return NULL;
        };
        if (ret < 0) {
            printf(PTHREAD_FMT "recv error\n", id);
            return NULL;
        }

        buf[ret] = 0;
        printf(PTHREAD_FMT "received %d bytes: %s\n", id, ret, buf);

        int sent = ts_tcp_send(stream, buf, ret);
        if (sent != ret) {
            printf(PTHREAD_FMT "echo didn't complete, bailing\n", id);
            return NULL;
        }

        printf(PTHREAD_FMT "echo\n", id);
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
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
    printf("listening on %s:%u\n", addr_str, 1234);

    struct ts_tcp_listener* listener = ts_tcp_listen(dev, &addr);
    assert(listener);

    while (1) {
        struct ts_tcp_stream* stream = ts_tcp_accept(listener);
        assert(stream);

        pthread_t id;

        assert(!pthread_create(&id, NULL, &run_conn_echo, stream));
    }
}
