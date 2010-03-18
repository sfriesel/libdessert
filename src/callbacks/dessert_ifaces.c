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

/** MTU for interface configuration */
#define DESSERT_DEFAULT_MTU 1300

/** CLI command, add TAP interface in config mode
 *
 * This callback can be used to create a TAP device as sys interface.
 *
 * COMMAND: interface sys $iface, $ipv4-addr, $netmask
 */
int dessert_cli_cmd_addsysif(struct cli_def *cli, char *command, char *argv[], int argc) {
    char buf[255];
    int i;

    if (argc != 3) {
        cli_print(cli, "usage %s [sys-interface] [ip-address] [netmask]\n",
                command);
        return CLI_ERROR;
    }
    dessert_info("initializing sys interface");
    dessert_sysif_init(argv[0], DESSERT_TAP | DESSERT_MAKE_DEFSRC);
    sprintf(buf, "ifconfig %s %s netmask %s mtu %d up", argv[0], argv[1],
            argv[2], DESSERT_DEFAULT_MTU);
    i = system(buf);
    dessert_info("ifconfig on sys interface returned %i", i);
    return (i == 0 ? CLI_OK : CLI_ERROR);
}

/** CLI command, add TUN interface in config mode
 *
 * This callback can be used to create a TUN device as sys interface.
 *
 * COMMAND: interface sys $iface, $ipv4-addr, $netmask
 */
int dessert_cli_cmd_addsysif_tun(struct cli_def *cli, char *command, char *argv[], int argc) {
    char buf[255];
    int i;

    if (argc != 3) {
        cli_print(cli, "usage %s [sys-interface] [ip-address] [netmask]\n",
                command);
        return CLI_ERROR;
    }
    dessert_info("initializing sys interface");
    dessert_sysif_init(argv[0], DESSERT_TUN | DESSERT_MAKE_DEFSRC);
    sprintf(buf, "ifconfig %s %s netmask %s mtu %d up", argv[0], argv[1],
            argv[2], DESSERT_DEFAULT_MTU);
    i = system(buf);
    dessert_info("ifconfig on sys interface returned %i", i);
    return (i == 0 ? CLI_OK : CLI_ERROR);
}

/** CLI command - config mode - interface mesh $iface */
int dessert_cli_cmd_addmeshif(struct cli_def *cli, char *command, char *argv[], int argc) {
    char buf[255];
    int i;

    if (argc != 1) {
        cli_print(cli, "usage %s [mesh-interface]\n", command);
        return CLI_ERROR;
    }
    dessert_info("initializing mesh interface %s", argv[0]);
    dessert_meshif_add(argv[0], DESSERT_IF_PROMISC);
    sprintf(buf, "ifconfig %s up", argv[0]);
    i = system(buf);
    dessert_info("running ifconfig on mesh interface %s returned %i",argv[0], i);
    return (i == 0 ? CLI_OK : CLI_ERROR);
}
