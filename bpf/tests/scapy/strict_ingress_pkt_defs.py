# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## Strict ingress, cleartext cluster traffic (decrypt_host_wireguard_strict.c)
## A cleartext pod-to-pod packet that arrives on the native routing path
## without having gone through WireGuard decrypt. This is the inner packet
## that should have been encrypted, so its source is a cluster pod.

strict_ingress_v4 = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_pod_one, dst=v4_pod_two) /
    TCP(sport=12345, dport=80)
)

strict_ingress_v6 = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(src=v6_pod_one, dst=v6_pod_two) /
    TCP(sport=12345, dport=80)
)
