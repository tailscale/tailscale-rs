#!/usr/bin/env python3

'''
Anonymize the IPs and ports in a real packet filter.

Always reads from stdin and writes to stdout. Expects to see the data in the
MapResponse.packet_filter field (an array of filters).
'''

import sys
import ipaddress
import random
import json
import string

from argparse import ArgumentParser

U16_MAX = (1 << 16) - 1

CGNAT_IPV4 = ipaddress.IPv4Network('100.64.0.0/10')
IPV4_PREFIX = [100, 64]

ULA_IPV6 = ipaddress.IPv6Network('fd7a:115c:a1e0::/48')
IPV6_PREFIX = [0xfd7a, 0x115c, 0xa1e0]


def random_octet() -> int:
    return random.randint(0, 255)


def random_ipv4(ip: str, prefix_len: int = 32) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    prefix = []

    src_net = ipaddress.IPv4Network(f'{ip}/{prefix_len}', strict=False)
    if CGNAT_IPV4.overlaps(src_net):
        prefix = IPV4_PREFIX

    octets = prefix + [random_octet() for i in range(4 - len(prefix))]
    addr = ipaddress.IPv4Address('.'.join(str(octet) for octet in octets))
    net = ipaddress.IPv4Network(f'{addr}/{prefix_len}', strict=False)

    if prefix_len != 32:
        return net
    else:
        return addr


def random_segment() -> int:
    return random.randint(0, U16_MAX)


def random_ipv6(ip: str, prefix_len: int = 128) -> ipaddress.IPv6Address | ipaddress.IPv6Network:
    prefix = []

    src_net = ipaddress.IPv6Network(f'{ip}/{prefix_len}', strict=False)
    if ULA_IPV6.overlaps(src_net):
        prefix = IPV6_PREFIX

    segments = prefix + [random_segment() for i in range(8 - len(prefix))]
    addr = ipaddress.IPv6Address(':'.join(f'{segment:x}' for segment in segments))
    net = ipaddress.IPv6Network(f'{addr}/{prefix_len}', strict=False)

    if prefix_len != 128:
        return net
    else:
        return addr


def random_cap() -> str:
    cap_name = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
    return f'cap:{cap_name}'


def random_matching_srcip(src: str) -> str | ipaddress.IPv4Address | ipaddress.IPv4Network | ipaddress.IPv6Address | ipaddress.IPv6Network:
    if src == '*':
        return '*'

    if src.startswith('cap:'):
        return random_cap()

    if '-' in src:
        raise ValueError('ip ranges are currently unsupported')

    split = src.split('/')
    prefix_len = None

    if len(split) > 1:
        src = split[0]
        prefix_len = int(split[1])

    if ':' in src:
        return random_ipv6(src, prefix_len or 128)
    else:
        return random_ipv4(src, prefix_len or 32)


def random_matching_ports(ports: dict[str, int]) -> dict[str, int]:
    if ports['First'] == 0 and ports['Last'] == U16_MAX:
        return ports

    first_port = random.randint(0, U16_MAX)
    last_port = random.randint(0, U16_MAX)

    if ports['First'] == ports['Last']:
        # if the src rule was a single port, produce an output rule with a single port
        last_port = first_port

    return {
        'First': min(first_port, last_port),
        'Last': max(first_port, last_port),
    }


def random_matching_dstport(dstport: dict[str, str | dict[str, int]]) -> dict[str, str | dict[str, int]]:
    dstport['IP'] = str(random_matching_srcip(dstport['IP']))
    dstport['Ports'] = random_matching_ports(dstport['Ports'])
    # just keep ipproto the same

    return dstport


def srcport_sort_key(s: str | ipaddress.IPv4Address | ipaddress.IPv4Network | ipaddress.IPv6Address | ipaddress.IPv6Network) -> int:
    try:
        return int(s)
    except:
        pass

    try:
        return int(s.network_address)
    except:
        pass

    return -1


def main() -> None:
    data = json.load(sys.stdin)

    for i, filter in enumerate(data):
        result = {}

        if 'CapGrant' in filter:
            raise ValueError('CapGrants are currently unsupported')

        ips = [random_matching_srcip(ip) for ip in filter['SrcIPs']]
        ips.sort(key=srcport_sort_key)

        result['SrcIPs'] = [str(ip) for ip in ips]
        result['DstPorts'] = [random_matching_dstport(dstport) for dstport in filter['DstPorts']]

        data[i] = result

    json.dump(data, sys.stdout, indent=' '*4)


if __name__ == '__main__':
    main()
