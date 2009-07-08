/******************************************************************************
 Copyright 2009, Philipp Schmidt, Freie Universitaet Berlin (FUB).
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

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 32
#endif

/* data storage */
struct sockaddr_in6 _dessert_cli_addr;
int _dessert_cli_sock;
struct cli_def *dessert_cli;
struct cli_command *dessert_cli_show;
struct cli_command *dessert_cli_cfg_iface;
struct cli_command *dessert_cli_cfg_no;
struct cli_command *dessert_cli_cfg_no_iface;
struct cli_command *dessert_cli_cfg_logging;
struct cli_command *dessert_cli_cfg_no_logging;

char _dessert_cli_hostname[HOST_NAME_MAX+DESSERT_PROTO_STRLEN+1];
pthread_t _dessert_cli_worker;

/* imported CLI commands from dessert_core */
int _dessert_cli_cmd_logging(struct cli_def *cli, char *command, char *argv[], int argc);
int _dessert_cli_logging_file(struct cli_def *cli, char *command, char *argv[], int argc);
int _dessert_cli_no_logging_file(struct cli_def *cli, char *command, char *argv[], int argc);
int _dessert_cli_logging_ringbuffer(struct cli_def *cli, char *command, char *argv[], int argc);
int _dessert_cli_no_logging_ringbuffer(struct cli_def *cli, char *command, char *argv[], int argc);
int _dessert_cli_cmd_shutdown(struct cli_def *cli, char *command, char *argv[], int argc);


/** command "show dessert-info" */
int _dessert_cli_cmd_dessertinfo(struct cli_def *cli, char *command, char *argv[], int argc)
{
    cli_print(cli, "\nprotocol running:   %s v %d", dessert_proto, dessert_ver);
    cli_print(cli, "libdessert version: %s", SHLIB_VERSION);
    cli_print(cli, " ------------------------------------------------------------------------------ ");
    cli_print(cli, " Copyright 2009, Philipp Schmidt, Freie Universitaet Berlin (FUB).              ");
    cli_print(cli, " All rights reserved.                                                           ");
    cli_print(cli, "                                                                                ");
    cli_print(cli, " These sources were originally developed by Philipp Schmidt                     ");
    cli_print(cli, " at Freie Universitaet Berlin (http://www.fu-berlin.de/),                       ");
    cli_print(cli, " Computer Systems and Telematics / Distributed, Embedded Systems (DES) group    ");
    cli_print(cli, " (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)                     ");
    cli_print(cli, " ------------------------------------------------------------------------------ ");
    cli_print(cli, " This program is free software: you can redistribute it and/or modify it under  ");
    cli_print(cli, " the terms of the GNU General Public License as published by the Free Software  ");
    cli_print(cli, " Foundation, either version 3 of the License, or (at your option) any later     ");
    cli_print(cli, " version.                                                                       ");
    cli_print(cli, "                                                                                ");
    cli_print(cli, " This program is distributed in the hope that it will be useful, but WITHOUT    ");
    cli_print(cli, " ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS  ");
    cli_print(cli, " FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. ");
    cli_print(cli, "                                                                                ");
    cli_print(cli, " You should have received a copy of the GNU General Public License along with   ");
    cli_print(cli, " this program. If not, see http://www.gnu.org/licenses/ .                       ");
    cli_print(cli, " ------------------------------------------------------------------------------ ");
    return CLI_OK;
}


/** internal thread function running the cli */
void *_dessert_cli_accept_thread(void* arg) {
    int *s = (int *) arg;
    int c;
    
    while ((c = accept(*s, NULL, 0)))
    {
        // Pass the connection off to libcli
        cli_loop(dessert_cli, c);
        close(c);
    }

    // Free data structures
    cli_done(dessert_cli);
    
    return;
}


/** run cli thread 
 * @arg port port to listen on
*/
int dessert_cli_run(int port) {
    int on=1;
    
    /* listen for connections */
    _dessert_cli_sock = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(_dessert_cli_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&_dessert_cli_addr, 0, sizeof(_dessert_cli_addr));
    _dessert_cli_addr.sin6_family = AF_INET6;
    _dessert_cli_addr.sin6_addr = in6addr_any;
    _dessert_cli_addr.sin6_port = htons(port);
    if(bind(_dessert_cli_sock, (struct sockaddr *)&_dessert_cli_addr, sizeof(_dessert_cli_addr))){
        dessert_err("cli socket bind to port %d failed - %s", port, strerror(errno));
        return -errno;
    }
    listen(_dessert_cli_sock, 8);
    dessert_debug("starting worker thread for cli");
    pthread_create(&_dessert_cli_worker, NULL, _dessert_cli_accept_thread, &_dessert_cli_sock);
    return DESSERT_OK;
}

/** internal function to initalize libcli */
int _dessert_cli_init() {

   dessert_cli = cli_init();
   
   /* set hostname */
   memset(_dessert_cli_hostname, 0x0, HOST_NAME_MAX+DESSERT_PROTO_STRLEN+1);
   gethostname(_dessert_cli_hostname, HOST_NAME_MAX);
   strncpy(_dessert_cli_hostname+strlen(_dessert_cli_hostname), ":", 1);
   strncpy(_dessert_cli_hostname+strlen(_dessert_cli_hostname), dessert_proto, DESSERT_PROTO_STRLEN);
   cli_set_hostname(dessert_cli, _dessert_cli_hostname);
   
   /* initalize show commands */
   dessert_cli_show = cli_register_command(dessert_cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display information");
   cli_register_command(dessert_cli, dessert_cli_show, "dessert-info", _dessert_cli_cmd_dessertinfo, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display information about this program");
   cli_register_command(dessert_cli, dessert_cli_show, "logging", _dessert_cli_cmd_logging, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show logging ringbuffer");
   
   /* initalize config mode commands */
   dessert_cli_cfg_iface = cli_register_command(dessert_cli, NULL, "interface", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "crearte or configure interfaces");
   dessert_cli_cfg_no = cli_register_command(dessert_cli, NULL, "no", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "negate command");
   dessert_cli_cfg_no_iface = cli_register_command(dessert_cli, dessert_cli_cfg_no, "interface", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "remove interface or negate interface config");
   dessert_cli_cfg_logging = cli_register_command(dessert_cli, NULL, "logging", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "change logging config");
   dessert_cli_cfg_no_logging = cli_register_command(dessert_cli, dessert_cli_cfg_no, "logging", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "disable logging for...");
   cli_register_command(dessert_cli, dessert_cli_cfg_logging, "ringbuffer", _dessert_cli_logging_ringbuffer, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "set logging ringbuffer size (in lines)");
   cli_register_command(dessert_cli, dessert_cli_cfg_no_logging, "ringbuffer", _dessert_cli_logging_ringbuffer, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "disable logging to ringbuffer");
   cli_register_command(dessert_cli, dessert_cli_cfg_logging, "file", _dessert_cli_logging_file, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "set logfile and enable file logging");
   cli_register_command(dessert_cli, dessert_cli_cfg_no_logging, "file", _dessert_cli_logging_file, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "set logfile disbale file logging");
   
   /* initalize other commands */
   cli_register_command(dessert_cli, NULL, "shutdown", _dessert_cli_cmd_shutdown, PRIVILEGE_PRIVILEGED, MODE_EXEC, "shut daemon down");
   
   return DESSERT_OK;
}
