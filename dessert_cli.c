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

#include "dessert_internal.h"
#include "dessert.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 32
#endif

/* global data storage // P U B L I C */
struct cli_def *dessert_cli;
struct cli_command *dessert_cli_show;
struct cli_command *dessert_cli_cfg_iface;
struct cli_command *dessert_cli_cfg_no;
struct cli_command *dessert_cli_cfg_no_iface;
struct cli_command *dessert_cli_cfg_logging;
struct cli_command *dessert_cli_cfg_no_logging;

/* global data storage // P R I V A T E */
/* nothing here - yet */

/* local data storage*/
int _dessert_cli_sock;
struct sockaddr_in6 _dessert_cli_addr;
char _dessert_cli_hostname[HOST_NAME_MAX + DESSERT_PROTO_STRLEN + 1];
pthread_t _dessert_cli_worker;
int _dessert_cli_running = 0;
uint16_t _cli_port = 4519; // should be default port number



/* internal functions forward declarations*/
static void *_dessert_cli_accept_thread(void* arg);
static int _dessert_cli_cmd_showmeshifs(struct cli_def *cli, char *command,
		char *argv[], int argc);
static int _dessert_cli_cmd_showsysif(struct cli_def *cli, char *command,
		char *argv[], int argc);
static int _dessert_cli_cmd_dessertinfo(struct cli_def *cli, char *command,
		char *argv[], int argc);
static int _dessert_cli_cmd_setport(struct cli_def *cli, char *command, char *argv[], int argc);

static void _dessert_cli_cmd_showmeshifs_print_helper(struct cli_def *cli, dessert_meshif_t *meshif);
/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

/** CLI command - config mode - interface sys $iface, $ipv4-addr, $netmask */
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
	sprintf(buf, "ifconfig %s %s netmask %s mtu 1300 up", argv[0], argv[1],
			argv[2]);
	i = system(buf);
	dessert_info("running ifconfig on sys interface returned %i", i);
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

/**
 *
 */
FILE* dessert_cli_get_cfg(int argc, char** argv) {
	FILE* cfg;

	const char* path_head = "/etc/";
	const char* path_tail = ".conf";

	char* str = alloca(strlen(argv[0])+1);
	strcpy(str, argv[0]);
	char* ptr = strtok(str, "/");
	char* daemon = ptr;
	while (ptr != NULL) {
		daemon = ptr;
		ptr = strtok(NULL, "/");
	}

	if (argc != 2) {
		char
				* path =
						alloca(strlen(path_head)+1 +strlen(path_tail)+1 +strlen(daemon)+1);
		strcat(path, path_head);
		strcat(path, daemon);
		strcat(path, path_tail);
		cfg = fopen(path, "r");
		if (cfg == NULL) {
			dessert_err("specify configuration file\nusage: \"%s configfile\"\nusage: \"%s\" if /etc/%s.conf is present", daemon, daemon, daemon);
			exit(1);
		}
	} else {
		cfg = fopen(argv[1], "r");
		if (cfg == NULL) {
			dessert_err("failed to open configfile %s", argv[1]);
			exit(2);
		} else {
			dessert_info("using file %s as configuration file", argv[1]);
		}
	}
	return cfg;
}

int dessert_set_cli_port(uint16_t port) {
    if (_dessert_cli_running == 1) {
		dessert_err("CLI is already running!");
    	return DESSERT_ERR;
    }

	if (port >= 1024 && port <= 49151)
		_cli_port = port;
	else {
		port = 0;
		dessert_err("Port number has to be in [1024, 49151]");
	}
	dessert_info("CLI on port %d", _cli_port);
	return (port == 0 ? DESSERT_ERR : DESSERT_OK);
}

/** Start up the command line interface.
 *
 * @param[in] port port to listen on
 *
 * @retval DESSERT_OK on success
 * @retval -errno otherwise
 *
 * %DESCRIPTION:
 *
 */
int dessert_cli_run() {
	_dessert_cli_running = 1;
	int on = 1;

	/* listen for connections */
	_dessert_cli_sock = socket(AF_INET6, SOCK_STREAM, 0);
	setsockopt(_dessert_cli_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&_dessert_cli_addr, 0, sizeof(_dessert_cli_addr));
	_dessert_cli_addr.sin6_family = AF_INET6;
	_dessert_cli_addr.sin6_addr = in6addr_any;
	_dessert_cli_addr.sin6_port = htons(_cli_port);
	if (bind(_dessert_cli_sock, (struct sockaddr *) &_dessert_cli_addr,
			sizeof(_dessert_cli_addr))) {
		dessert_err("cli socket bind to port %d failed - %s", _cli_port, strerror(errno));
		return -errno;
	}
	listen(_dessert_cli_sock, 8);
	dessert_debug("starting worker thread for cli");
	pthread_create(&_dessert_cli_worker, NULL, _dessert_cli_accept_thread,
			&_dessert_cli_sock);
	return DESSERT_OK;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

/** internal function to initialize libcli */
int _dessert_cli_init() {

	dessert_cli = cli_init();

	/* set host name */
	memset(_dessert_cli_hostname, 0x0, HOST_NAME_MAX + DESSERT_PROTO_STRLEN + 1);
	gethostname(_dessert_cli_hostname, HOST_NAME_MAX);
	strncpy(_dessert_cli_hostname + strlen(_dessert_cli_hostname), ":", 1);
	strncpy(_dessert_cli_hostname + strlen(_dessert_cli_hostname),
			dessert_proto, DESSERT_PROTO_STRLEN);
	cli_set_hostname(dessert_cli, _dessert_cli_hostname);

	/* initialize show commands */
	dessert_cli_show = cli_register_command(dessert_cli, NULL, "show", NULL,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "display information");
	cli_register_command(dessert_cli, dessert_cli_show, "dessert-info",
			_dessert_cli_cmd_dessertinfo, PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			"Display information about this program.");
	cli_register_command(dessert_cli, dessert_cli_show, "logging",
			_dessert_cli_cmd_logging, PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			"show logging ringbuffer");
	cli_register_command(dessert_cli, dessert_cli_show, "meshifs",
			_dessert_cli_cmd_showmeshifs, PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			"Print list of registered interfaces used by the daemon.");
	cli_register_command(dessert_cli, dessert_cli_show, "sysif", _dessert_cli_cmd_showsysif,
			PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
			"Print the name of the TUN/TAP interface used as system interface.");

	/* initialize config mode commands */
	dessert_cli_cfg_iface = cli_register_command(dessert_cli, NULL,
			"interface", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"create or configure interfaces");
	dessert_cli_cfg_no = cli_register_command(dessert_cli, NULL, "no", NULL,
			PRIVILEGE_PRIVILEGED, MODE_CONFIG, "negate command");
	dessert_cli_cfg_no_iface = cli_register_command(dessert_cli,
			dessert_cli_cfg_no, "interface", NULL, PRIVILEGE_PRIVILEGED,
			MODE_CONFIG, "remove interface or negate interface config");
	dessert_cli_cfg_logging = cli_register_command(dessert_cli, NULL,
			"logging", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"change logging config");
	dessert_cli_cfg_no_logging = cli_register_command(dessert_cli,
			dessert_cli_cfg_no, "logging", NULL, PRIVILEGE_PRIVILEGED,
			MODE_CONFIG, "disable logging for...");
	cli_register_command(dessert_cli, dessert_cli_cfg_logging, "ringbuffer",
			_dessert_cli_logging_ringbuffer, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"set logging ringbuffer size (in lines)");
	cli_register_command(dessert_cli, dessert_cli_cfg_no_logging, "ringbuffer",
			_dessert_cli_logging_ringbuffer, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"disable logging to ringbuffer");
	cli_register_command(dessert_cli, dessert_cli_cfg_logging, "file",
			_dessert_cli_logging_file, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"set logfile and enable file logging");
	cli_register_command(dessert_cli, dessert_cli_cfg_no_logging, "file",
			_dessert_cli_logging_file, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"set logfile disable file logging");

	cli_register_command(dessert_cli, NULL, "port", _dessert_cli_cmd_setport,
					PRIVILEGE_PRIVILEGED, MODE_CONFIG,
					"configure TCP port the daemon is listening on");

	/* initialize other commands */
	cli_register_command(dessert_cli, NULL, "shutdown",
			_dessert_cli_cmd_shutdown, PRIVILEGE_PRIVILEGED, MODE_EXEC,
			"shut daemon down");



	return DESSERT_OK;
}

/******************************************************************************
 *
 * LOCAL
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

static int _dessert_cli_cmd_setport(struct cli_def *cli, char *command, char *argv[], int argc) {
    if (_dessert_cli_running == 1) {
    	cli_print(dessert_cli,"CLI is already running!");
    	return CLI_ERROR;
    }

    return (dessert_set_cli_port((uint16_t) atoi(argv[0]))==DESSERT_ERR?CLI_ERROR:CLI_OK);
}

/** command "show meshifs" */
static int _dessert_cli_cmd_showmeshifs(struct cli_def *cli, char *command,
		char *argv[], int argc) {

	dessert_meshif_t *meshif = NULL;

	MESHIFLIST_ITERATOR_START(meshif) {
		_dessert_cli_cmd_showmeshifs_print_helper(cli, meshif);
	} MESHIFLIST_ITERATOR_STOP;

	return CLI_OK;
}

/** command "show sysif" */
static int _dessert_cli_cmd_showsysif(struct cli_def *cli, char *command,
		char *argv[], int argc) {

	dessert_sysif_t *sysif = _dessert_sysif;

	cli_print(cli, "\nStatistics for system interface [%s]", sysif->if_name);
	cli_print(cli, "    MAC address           : [%02x:%02x:%02x:%02x:%02x:%02x]",
			sysif->hwaddr[0], sysif->hwaddr[1], sysif->hwaddr[2],
			sysif->hwaddr[3], sysif->hwaddr[4], sysif->hwaddr[5]);
	cli_print(cli, "    Packets received      : [%"PRIi64"]", sysif->ipkts);
	cli_print(cli, "    Packets send          : [%"PRIi64"]", sysif->opkts);
	cli_print(cli, "    Bytes received        : [%"PRIi64"]", sysif->ibytes);
	cli_print(cli, "    Bytes send            : [%"PRIi64"]", sysif->obytes);

	return CLI_OK;
}

/** command "show dessert-info" */
static int _dessert_cli_cmd_dessertinfo(struct cli_def *cli, char *command,
		char *argv[], int argc) {
	cli_print(cli, "\nprotocol running:   %s v %d", dessert_proto, dessert_ver);
	cli_print(cli, "libdessert version: %s", SHLIB_VERSION);
	cli_print(
			cli,
			" ------------------------------------------------------------------------------ ");
	cli_print(
			cli,
			" Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).            ");
	cli_print(
			cli,
			" All rights reserved.                                                           ");
	cli_print(
			cli,
			"                                                                                ");
	cli_print(
			cli,
			" These sources were originally developed by Philipp Schmidt                     ");
	cli_print(
			cli,
			" at Freie Universitaet Berlin (http://www.fu-berlin.de/),                       ");
	cli_print(
			cli,
			" Computer Systems and Telematics / Distributed, Embedded Systems (DES) group    ");
	cli_print(
			cli,
			" (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)                     ");
	cli_print(
			cli,
			" ------------------------------------------------------------------------------ ");
	cli_print(
			cli,
			" This program is free software: you can redistribute it and/or modify it under  ");
	cli_print(
			cli,
			" the terms of the GNU General Public License as published by the Free Software  ");
	cli_print(
			cli,
			" Foundation, either version 3 of the License, or (at your option) any later     ");
	cli_print(
			cli,
			" version.                                                                       ");
	cli_print(
			cli,
			"                                                                                ");
	cli_print(
			cli,
			" This program is distributed in the hope that it will be useful, but WITHOUT    ");
	cli_print(
			cli,
			" ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS  ");
	cli_print(
			cli,
			" FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. ");
	cli_print(
			cli,
			"                                                                                ");
	cli_print(
			cli,
			" You should have received a copy of the GNU General Public License along with   ");
	cli_print(
			cli,
			" this program. If not, see http://www.gnu.org/licenses/ .                       ");
	cli_print(
			cli,
			" ------------------------------------------------------------------------------ ");
	return CLI_OK;
}

/** internal thread function running the cli */
static void *_dessert_cli_accept_thread(void* arg) {
	int *s = (int *) arg;
	int c;

	while ((c = accept(*s, NULL, 0))) {
		cli_loop(dessert_cli, c); /* pass the connection off to libcli */
		close(c);
	}

	cli_done(dessert_cli); /* free data structures */

	return (NULL);
}

/** internal helper function to _dessert_cli_cmd_showmeshifs */
static void _dessert_cli_cmd_showmeshifs_print_helper(struct cli_def *cli, dessert_meshif_t *meshif) {

	cli_print(cli, "\nStatistics for mesh interface [%s]", meshif->if_name);
	cli_print(cli,
			"    MAC address           : [%02x:%02x:%02x:%02x:%02x:%02x]",
			meshif->hwaddr[0], meshif->hwaddr[1], meshif->hwaddr[2],
			meshif->hwaddr[3], meshif->hwaddr[4], meshif->hwaddr[5]);
	cli_print(cli, "    Packets received      : [%"PRIi64"]", meshif->ipkts);
	cli_print(cli, "    Packets send          : [%"PRIi64"]", meshif->opkts);
	cli_print(cli, "    Bytes received        : [%"PRIi64"]", meshif->ibytes);
	cli_print(cli, "    Bytes send            : [%"PRIi64"]", meshif->obytes);

	return CLI_OK;
}
