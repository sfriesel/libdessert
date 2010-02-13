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
#include <string.h>

struct cli_def *_dessert_callbacks_cli;

/** Send a ping packet
* 
*/
int dessert_cli_cmd_ping(struct cli_def *cli, char *command, char *argv[], int argc) {
    u_char ether_trace[ETHER_ADDR_LEN];
    dessert_msg_t *msg;
    dessert_ext_t *ext;
    struct ether_header *l25h;

    if( argc<1 || argc >2 ||
        sscanf(argv[0], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &ether_trace[0], &ether_trace[1], &ether_trace[2],
            &ether_trace[3], &ether_trace[4], &ether_trace[5]) != 6
    ) {
        cli_print(cli, "usage %s [mac-address in xx:xx:xx:xx:xx:xx notation] ([text])\n", command);
        return CLI_ERROR;
    }
    cli_print(cli, "sending ping packet to %x:%x:%x:%x:%x:%x...\n",
         ether_trace[0], ether_trace[1], ether_trace[2],
         ether_trace[3], ether_trace[4], ether_trace[5]);
    dessert_info("sending ping packet to %x:%x:%x:%x:%x:%x",
          ether_trace[0], ether_trace[1], ether_trace[2],
          ether_trace[3], ether_trace[4], ether_trace[5]);

    dessert_msg_new(&msg);

    dessert_msg_addext(msg, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);
    l25h = (struct ether_header *) ext->data;
    memcpy(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN);
    memcpy(l25h->ether_dhost, ether_trace, ETHER_ADDR_LEN);
    l25h->ether_type = htons(0x0000);

    if(argc == 2) {
        int len = strlen(argv[1]);
        len = len>DESSERT_MAXEXTDATALEN?DESSERT_MAXEXTDATALEN:len;
        dessert_msg_addext(msg, &ext, DESSERT_EXT_PING, len);
        memcpy(ext->data, argv[1], len);
    } else {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_PING, 5);
        memcpy(ext->data, "ping", 5);
    }

    dessert_meshsend(msg, NULL);
    dessert_msg_destroy(msg);

    _dessert_callbacks_cli = cli;

    return CLI_OK;
}

/** Handle ping packets
 *
 */
int dessert_rx_ping(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id) {
    dessert_ext_t *ext;
    struct ether_header *l25h;
    u_char temp[ETHER_ADDR_LEN];

    l25h = dessert_msg_getl25ether(msg);
    
    if(l25h
      && proc->lflags & DESSERT_LFLAG_DST_SELF
      && dessert_msg_getext(msg, &ext, DESSERT_EXT_PING, 0)) {

        dessert_debug("got ping packet from %x:%x:%x:%x:%x.%x - sending pong",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5]);

        memcpy(temp, l25h->ether_shost, ETHER_ADDR_LEN);
        memcpy(l25h->ether_shost, l25h->ether_dhost, ETHER_ADDR_LEN);
        memcpy(l25h->ether_dhost, temp, ETHER_ADDR_LEN);
        ext->type = DESSERT_EXT_PONG;
        memcpy(ext->data, "pong", 5);
        dessert_meshsend(msg, NULL);

        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** Handle pong packets
 *
 */
int dessert_rx_pong(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id) {
    dessert_ext_t *ext;
    struct ether_header *l25h;
    u_char temp[ETHER_ADDR_LEN];

    l25h = dessert_msg_getl25ether(msg);

    if(l25h
      && proc->lflags & DESSERT_LFLAG_DST_SELF
      && dessert_msg_getext(msg, &ext, DESSERT_EXT_PONG, 0)) {
        dessert_debug("got pong packet from %x:%x:%x:%x:%x.%x",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5]);
        if(_dessert_callbacks_cli != NULL)
            cli_print(_dessert_callbacks_cli, "\ngot pong packet from %x:%x:%x:%x:%x.%x",
                    l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
                    l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5]);

        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}
