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
#include <sys/stat.h>

/* data storage */
char        dessert_proto[DESSERT_PROTO_STRLEN+1];
u_int8_t    dessert_ver;

u_int8_t    dessert_l25_defsrc[ETHER_ADDR_LEN];
u_char      ether_broadcast[ETHER_ADDR_LEN];
u_char      ether_null[ETHER_ADDR_LEN];

dessert_frameid_t _dessert_nextframeid = 0;
pthread_mutex_t _dessert_nextframeid_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_rwlock_t dessert_cfglock = PTHREAD_RWLOCK_INITIALIZER;

pthread_mutex_t _dessert_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t _dessert_exit_do = PTHREAD_COND_INITIALIZER;
int _dessert_exit_code = 0;

char *dessert_pidfile_name;

int         _dessert_status   = 0x0;

/** command "shutdown" */
int _dessert_cli_cmd_shutdown(struct cli_def *cli, char *command, char *argv[], int argc)
{
    cli_print(cli, "daemon will shut down now!");
    pthread_mutex_lock(&_dessert_exit_mutex);
    pthread_cond_broadcast(&_dessert_exit_do);
    pthread_mutex_unlock(&_dessert_exit_mutex);
    return CLI_OK;

}


/** generates a new, runtime-uniqe frame id 
  * @returns runtime-uniqe frame id
**/
dessert_frameid_t dessert_newframeid () {
    dessert_frameid_t x;
    pthread_mutex_lock(&_dessert_nextframeid_mutex);
    x = _dessert_nextframeid++;
    pthread_mutex_unlock(&_dessert_nextframeid_mutex);
    return(x);
}


/** internal daemonize helper */
void _dessert_daemonize (){
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        perror("could not create daemon process!");
        exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    /* Change the file mode mask */
    umask(0);       
    
    /* Open any logs here */
    
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
            perror("could not set sid!");
            exit(EXIT_FAILURE);
    }
    
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
            perror("could not chdir /!");
            exit(EXIT_FAILURE);
    }
    
    
    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* write config */
    pthread_rwlock_wrlock(&dessert_cfglock);
    _dessert_status |= _DESSERT_STATUS_DAEMON ;
    pthread_rwlock_unlock(&dessert_cfglock);
    
    /* adopt logging */
    dessert_logcfg(0x0);
    
}

/** internal pid-write helper */
int _dessert_pid(char* pidfile) {
    FILE *fd;

    fd = fopen(pidfile, "w");
    if(fd == 0) {
        dessert_warn("could not open pid file");
        return 1;
    }
    else {
        int r;
        r = fprintf(fd, "%d\n", getpid());
        if(r<0) {
            dessert_warn("could not write to pid file");
            return DESSERT_ERR;
        }

        if(fclose(fd) != 0) {
            dessert_warn("failed to close pid file");
        }
    }

    return DESSERT_OK;
}

/** initalizes dessert framework and sets up logging
 * @arg *proto 4 char string for protocol name
 * @arg version version number of protocol
 * @arg opts @see DESSERT_OPT_*
 * @returns DESSERT_OK on success, DESSERT_ERR otherwise
**/
int dessert_init(const char* proto, int version, uint16_t opts, char* pidfile)
{
    
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    /* save global config */
    memset(dessert_proto, 0x0, DESSERT_PROTO_STRLEN+1);
    strncpy(dessert_proto, proto, DESSERT_PROTO_STRLEN);
    dessert_ver = version;
    
    /* initalize pseudo constants */
    memset(ether_broadcast, 255, ETHER_ADDR_LEN);
    memset(ether_null, 0, ETHER_ADDR_LEN);
        
    pthread_rwlock_unlock(&dessert_cfglock);
        
    /* daemonize if needed */
    if((opts & DESSERT_OPT_DAEMONIZE) && !(opts & DESSERT_OPT_NODAEMONIZE)) {
        _dessert_daemonize();
    }
        
	/* write pid to file if needed */
	if(pidfile != NULL) {
        dessert_pidfile_name = pidfile;
        _dessert_pid(pidfile);
	}
    
    /* initalize cli */    
    _dessert_cli_init();
    
    /* start periodic thread */
    _desp2_periodic_init();
    
    return DESSERT_OK;
}

/** internal funcion to clean up things */
void _desp2_cleanup() {
    /* remove pidfile */
    if(dessert_pidfile_name != NULL) {
        unlink(dessert_pidfile_name);
    }
}

/** main loop - wait until dessert_exit() is called or killed 
 * @return arg to dessert_exit
 */
int dessert_run() {
    pthread_mutex_lock(&_dessert_exit_mutex);
    pthread_cond_wait(&_dessert_exit_do, &_dessert_exit_mutex);
    _desp2_cleanup();
    pthread_mutex_unlock(&_dessert_exit_mutex);
    return(_dessert_exit_code);
}



