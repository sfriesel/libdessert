/******************************************************************************
 Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by Philipp Schmidt
 at Freie Universitaet Berlin (http://www.fu-berlin.de/),
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)
 ------------------------------------------------------------------------------
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .
 ------------------------------------------------------------------------------
 For further information and questions please use the web site
 http://www.des-testbed.net/
 *******************************************************************************/

#include "dessert.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

extern dessert_sysif_t *_dessert_sysif;

/** Enable IP-based tracing 
*
* This extension decrements the TTL in IPv4 or the Hop-Limit field in IPv6 datagrams. If the
* value drops to 1, the datagram in the DES-SERT message is decapsulated and handed to the
* IP implementation of the operating system. Depending on the configuration, the IP
* implementation will send an ICMP time-exceeded message. This enables tracing despite
* the transparent underlay routing applied in DES-SERT.
*/
int dessert_rx_ipttl(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id) {
    void* payload;
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    // TODO: works currently only with encapsulated Ethernet frames
    if (eth == NULL)
        return DESSERT_MSG_KEEP;

    if (proc->lflags & DESSERT_LFLAG_DST_SELF) {
        // the packet got here, so we can ignore the TTL value
        dessert_debug("ignoring packets destined to me");
        return DESSERT_MSG_KEEP;
    }

    if (!(proc->lflags & DESSERT_LFLAG_NEXTHOP_SELF))
      return DESSERT_MSG_KEEP;

    // IPv4
    if (eth->ether_type == htons(ETHERTYPE_IP) && dessert_msg_getpayload(msg, &payload)) {
        struct iphdr* ip = (struct iphdr*) payload;
        // decrement TTL each hop
        if (ip->ttl > 1) {
            ip->ttl--;
            ip->check = (ip->check + 1);
        }
        /*
        * TTL == 1, let the IP implementation handle the situation and send an
        * ICMP time exceeded message
        */
        else {
            struct ether_header *eth;
            size_t eth_len;
            eth_len = dessert_msg_ethdecap(msg, &eth);
            /*
            * Fake destination ether address or the host will not evaluate the packet.
            * Multicast and broadcast frames can be ignored.
            */
            if (! (proc->lflags & DESSERT_LFLAG_DST_BROADCAST
                    || proc->lflags & DESSERT_LFLAG_DST_MULTICAST)) {
                memcpy(&(eth->ether_dhost), &(_dessert_sysif->hwaddr), ETHER_ADDR_LEN);
            }
            dessert_syssend(eth, eth_len);
            free(eth);
            return DESSERT_MSG_DROP;
        }
    }
    // IPv6
    else if (eth->ether_type == htons(ETHERTYPE_IPV6) && dessert_msg_getpayload(msg, &payload)) {
        struct ip6_hdr* ip = (struct ip6_hdr*) payload;
        // decrement Hop Limit each hop
        if (ip->ip6_ctlun.ip6_un1.ip6_un1_hlim) {
            ip->ip6_ctlun.ip6_un1.ip6_un1_hlim--;
        }
        /*
        * Hop Limit == 1, let the IP implementation handle the situation and send an
        * ICMPv6 time exceeded message
        */
        else {
            struct ether_header *eth;
            size_t eth_len;
            eth_len = dessert_msg_ethdecap(msg, &eth);
            /*
            * Fake destination ether address or the host will not evaluate the packet.
            * Multicast and broadcast frames can be ignored.
            */
            if (! (proc->lflags & DESSERT_LFLAG_DST_BROADCAST
                    || proc->lflags & DESSERT_LFLAG_DST_MULTICAST)) {
                memcpy(&(eth->ether_dhost), &(_dessert_sysif->hwaddr), ETHER_ADDR_LEN);
            }
            dessert_syssend(eth, eth_len);
            free(eth);
            return DESSERT_MSG_DROP;
        }
    }

    return DESSERT_MSG_KEEP;
}
