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

#include <dessert.h>

#ifndef DESSERT_CALLBACKS_H
#define DESSERT_CALLBACKS_H

// adding interfaces
int dessert_cli_cmd_addsysif(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_cli_cmd_addsysif_tun(struct cli_def *cli, char *command, char *argv[], int argc)
int dessert_cli_cmd_addmeshif(struct cli_def *cli, char *command, char *argv[], int argc);

// ping
int dessert_cli_cmd_ping(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_rx_ping(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_rx_pong(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

// tracing
int dessert_cli_cmd_traceroute(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_rx_trace(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_trace_initiate(dessert_msg_t* msg, uint8_t type, int mode);
int dessert_msg_trace_dump(const dessert_msg_t* msg, uint8_t type, char* buf, int blen);

// TTL
int dessert_rx_ipttl(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

// Drop depending on condition
int dessert_tx_drop_ipv6(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_sysif_t *iface, dessert_frameid_t id);
int dessert_rx_drop_tap(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_rx_drop_tun(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id) 

#endif