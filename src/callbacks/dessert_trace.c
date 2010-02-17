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
#include <errno.h>
#include <string.h>

struct cli_def *_dessert_callbacks_cli;

/** Trace route to destination
 *
 * Sends a packet with a trace request to a host.
 */
int dessert_cli_cmd_traceroute(struct cli_def *cli, char *command, char *argv[], int argc) {
    u_char ether_trace[ETHER_ADDR_LEN];
    dessert_msg_t *msg;
    dessert_ext_t *ext;
    struct ether_header *l25h;

    if( argc<1 || argc >2 ||
        sscanf(argv[0], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &ether_trace[0], &ether_trace[1], &ether_trace[2],
            &ether_trace[3], &ether_trace[4], &ether_trace[5]) != 6
    ) {
        cli_print(cli, "usage %s [mac-address in xx:xx:xx:xx:xx:xx notation] ([i])\n", command);
        return CLI_ERROR;
    }
    cli_print(cli, "sending trace packet to %x:%x:%x:%x:%x:%x...\n",
         ether_trace[0], ether_trace[1], ether_trace[2],
         ether_trace[3], ether_trace[4], ether_trace[5]);
    dessert_info("sending trace packet to %x:%x:%x:%x:%x:%x",
          ether_trace[0], ether_trace[1], ether_trace[2],
          ether_trace[3], ether_trace[4], ether_trace[5]);

    dessert_msg_new(&msg);

    dessert_msg_addext(msg, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);
    l25h = (struct ether_header *) ext->data;
    memcpy(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN);
    memcpy(l25h->ether_dhost, ether_trace, ETHER_ADDR_LEN);
    l25h->ether_type = htons(0x0000);

    if(argc == 2 && argv[1][0] == 'i') {
        dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE, DESSERT_MSG_TRACE_IFACE);
    } else {
        dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE, DESSERT_MSG_TRACE_HOST);
    }

    dessert_meshsend(msg, NULL);
    dessert_msg_destroy(msg);

    _dessert_callbacks_cli = cli;

    return CLI_OK;
}

/** Handle trace packets
 *
 * Prints the content of a trace request packet and sends the same packet with
 * an appended trace reply extension back if no trace reply is yet present.
 * If there is a trace request and a trace reply extension, both are printed but
 * no packet is send.
 * The whole trace mechanism is basically a ping/pong with additional tracing.
 */
int dessert_rx_trace(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id) {
    dessert_ext_t *request_ext;
    dessert_ext_t *reply_ext;
    struct ether_header *l25h;
    u_char temp[ETHER_ADDR_LEN];

    l25h = dessert_msg_getl25ether(msg);

    if(l25h && proc->lflags & DESSERT_LFLAG_DST_SELF) {
        char buf[1024];
        if(dessert_msg_getext(msg, &request_ext, DESSERT_EXT_TRACE, 0)) {
          memset(buf, 0x0, 1024);
          dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE, buf, 1024);

          dessert_debug("trace request from %x:%x:%x:%x:%x:%x\n%s",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5],
            buf);
          if(_dessert_callbacks_cli != NULL) {
            cli_print(_dessert_callbacks_cli, "\ntrace request from %x:%x:%x:%x:%x:%x\n%s",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5],
            buf);
          }
        }

        if(dessert_msg_getext(msg, &reply_ext, DESSERT_EXT_TRACE2, 0)) {
          memset(buf, 0x0, 1024);
          dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE2, buf, 1024);

          dessert_debug("trace reply from %x:%x:%x:%x:%x:%x\n%s",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5],
            buf);
          if(_dessert_callbacks_cli != NULL) {
            cli_print(_dessert_callbacks_cli, "\ntrace reply from %x:%x:%x:%x:%x:%x\n%s",
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5],
            buf);
          }
        }
        else if(request_ext) {
          memcpy(temp, l25h->ether_shost, ETHER_ADDR_LEN);
          memcpy(l25h->ether_shost, l25h->ether_dhost, ETHER_ADDR_LEN);
          memcpy(l25h->ether_dhost, temp, ETHER_ADDR_LEN);
          dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE2, dessert_ext_getdatalen(request_ext)==DESSERT_MSG_TRACE_IFACE?DESSERT_MSG_TRACE_IFACE:DESSERT_MSG_TRACE_HOST);
          dessert_meshsend(msg, NULL);
        }

        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** add initial trace header to dessert message
 * @arg *msg dessert_msg_t message used for tracing
 * @arg type DESSERT_EXT_TRACE or DESSERT_EXT_TRACE2
 * @arg mode trace mode
 *           use DESSERT_MSG_TRACE_HOST to only record default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * @return DESSERT_OK on success
 **/
int dessert_msg_trace_initiate(dessert_msg_t* msg, uint8_t type, int mode) {

    dessert_ext_t *ext;
    struct ether_header *l25h;

    if (type != DESSERT_EXT_TRACE && type != DESSERT_EXT_TRACE2)
        return EINVAL;

    if (mode != DESSERT_MSG_TRACE_HOST && mode != DESSERT_MSG_TRACE_IFACE)
        return EINVAL;

    if (msg->flags & DESSERT_FLAG_SPARSE)
        return DESSERT_MSG_NEEDNOSPARSE;

    dessert_msg_addext(msg, &ext, type, mode);
    memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);
    if (mode == DESSERT_MSG_TRACE_IFACE) {
        memcpy((ext->data) + ETHER_ADDR_LEN, msg->l2h.ether_shost,
                ETHER_ADDR_LEN);
        l25h = dessert_msg_getl25ether(msg);
        if (l25h == NULL) {
            memcpy((ext->data) + ETHER_ADDR_LEN, ether_null, ETHER_ADDR_LEN);
        } else {
            memcpy((ext->data) + ETHER_ADDR_LEN * 2, l25h->ether_shost,
                    ETHER_ADDR_LEN);
        }
    }

    return DESSERT_OK;

}

/** dump packet trace to string
 * @arg *msg dessert_msg_t message used for tracing
 * @arg type DESSERT_EXT_TRACE or DESSERT_EXT_TRACE2
 * @arg *buf char buffer to place string
 *           use DESSERT_MSG_TRACE_HOST to only record default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * @return length of the string - 0 if msg has no trace header, -1 if wrong type
 **/
int dessert_msg_trace_dump(const dessert_msg_t* msg, uint8_t type, char* buf, int blen) {

    dessert_ext_t *ext;
    int x, i = 0;
    if(type != DESSERT_EXT_TRACE
      || type != DESSERT_EXT_TRACE2)
      return -1;

#define _dessert_msg_trace_dump_append(...) snprintf(buf+strlen(buf), blen-strlen(buf), __VA_ARGS__)

    x = dessert_msg_getext(msg, &ext, type, 0);
    if (x < 1)
        return 0;

    _dessert_msg_trace_dump_append("\tpacket trace:\n");
    _dessert_msg_trace_dump_append("\t\tfrom %02x:%02x:%02x:%02x:%02x:%02x\n",
            ext->data[0], ext->data[1], ext->data[2],
            ext->data[3], ext->data[4], ext->data[5]);

    if (dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
        _dessert_msg_trace_dump_append("\t\t  received on   %02x:%02x:%02x:%02x:%02x:%02x\n",
                ext->data[6], ext->data[7], ext->data[8],
                ext->data[9], ext->data[10], ext->data[11]);
        _dessert_msg_trace_dump_append("\t\t  l2.5 src     %02x:%02x:%02x:%02x:%02x:%02x\n",
                ext->data[12], ext->data[13], ext->data[14],
                ext->data[15], ext->data[16], ext->data[17]);
    }

    for (i = 1; i < x; i++) {
        dessert_msg_getext(msg, &ext, type, i);
        _dessert_msg_trace_dump_append("\t\t#%3d %02x:%02x:%02x:%02x:%02x:%02x\n", i,
                ext->data[0], ext->data[1], ext->data[2],
                ext->data[3], ext->data[4], ext->data[5]);

        if (dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
            _dessert_msg_trace_dump_append("\t\t  received from  %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ext->data[12], ext->data[13], ext->data[14],
                    ext->data[15], ext->data[16], ext->data[17]);
            _dessert_msg_trace_dump_append("\t\t  receiving iface  %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ext->data[6], ext->data[7], ext->data[8],
                    ext->data[9], ext->data[10], ext->data[11]);
        }
    }

    return strlen(buf);
}
