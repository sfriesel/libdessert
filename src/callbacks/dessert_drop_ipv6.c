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
#include <netinet/ip6.h>
#include <string.h>

extern dessert_sysif_t *_dessert_sysif;

/** Drop IPv6 datagrams
*
* Drop all DES-SERT messages containing an IPv6 datagram
*/
int dessert_tx_drop_ipv6(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_sysif_t *iface, dessert_frameid_t id) {
    void* payload;
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    if (eth == NULL) { // has no Ethernet extension
        void *payload;
        dessert_msg_getpayload(msg, &payload);
        struct ip6_hdr* ip = (struct ip6_hdr*) payload;
        if(ip && ip->ip6_ctlun.ip6_un1.ip6_un1_flow & 0x60000000) {
            dessert_debug("dropped raw IPv6 packet (false positives are possible)");
            return DESSERT_MSG_DROP;
        }
        return DESSERT_MSG_KEEP;
    }
    else { // has Ethernet extension
        if (eth->ether_type == htons(ETHERTYPE_IPV6) ) {
            dessert_debug("dropped IPv6 packet in Ethernet frame");
            return DESSERT_MSG_DROP;
        }
    }

    return DESSERT_MSG_KEEP;
}
