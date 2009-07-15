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

#ifndef DESSERT
#define DESSERT

/* load needed libs - quite dirty */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "libcli.h"

#ifdef TARGET_DARWIN
#include <net/if_dl.h>
#define TUN_BSD
#endif

#ifdef TARGET_LINUX
#define TUN_LINUX
#endif



/* constants */

/** ethernet protocol used on layer 2 */
#define DESSERT_ETHPROTO 0x8042

/** length of protocol string used in dessert_msg */
#define DESSERT_PROTO_STRLEN 4

/** maximum frame size to assemble as dessert_msg */
#define DESSERT_MAXFRAMELEN ETHER_MAX_LEN

/** maximum size of the data part in dessert_ext */
#define DESSERT_MAXEXTDATALEN 130 

/** size of local message processing buffer */
#define DESSERT_LBUF_LEN 1024

/** maximum size of a log line */
#define DESSERT_LOGLINE_MAX 1024

/** return code for dessert_meshrxcb_t - forces to copy the message and call again*/
#define DESSERT_MSG_NEEDNOSPARSE     1

/** return code for dessert_meshrxcb_t - forces to generate processing info and call again*/
#define DESSERT_MSG_NEEDMSGPROC      2

/** return code for dessert_meshrxcb_t and dessert_tunrxcb_t */
#define DESSERT_MSG_KEEP             0

/** return code for dessert_meshrxcb_t and dessert_tunrxcb_t */
#define DESSERT_MSG_DROP             -1

/** return code for many dessert_* functions */
#define DESSERT_OK                  0

/** return code for many dessert_* functions */
#define DESSERT_ERR                 1

/* globals */

/** protocol string used in dessert_msg frames */
extern char        dessert_proto[DESSERT_PROTO_STRLEN+1];

/** version int used in dessert_msg frames */
extern u_int8_t    dessert_ver;

/** default src address used for local generated dessert_msg frames */
extern u_int8_t    dessert_l25_defsrc[ETHER_ADDR_LEN];

/** the config funnel */
extern pthread_rwlock_t dessert_cfglock;

/** the config-flag variable */
extern uint16_t dessert_cfgflags;

/** logfile file pointer to use with DESSERT_OPT_LOGFILE */
extern FILE *dessert_logfd; 

/** constant holding ethernet broadcast address after dessert_init */
extern u_char      ether_broadcast[ETHER_ADDR_LEN];

/** constant holding ethernet null address after dessert_init */
extern u_char      ether_null[ETHER_ADDR_LEN];




/** type for local unique packet identification */
typedef uint64_t dessert_frameid_t;
#define DESSERT_FRAMEID_MAX ((uint64_t)-1)
#define dessert_frameid_overflow(x, y) ((x>y)&&((x-y)>(DESSERT_FRAMEID_MAX/2)))

/** A basic message send on des-sert layer2.5 **/
typedef struct __attribute__ ((__packed__)) dessert_msg {
    /** the layer2 header on the wire */
    struct     ether_header l2h;
    /** short name of the protocol as passed to dessert_init() */
    char       proto[DESSERT_PROTO_STRLEN];
    /** version of the app as passed to dessert_init() */
    uint8_t    ver;
    /** flags - bits 1-4 reserved for dessert, bits 5-8 for app usage */
    uint8_t    flags;
    union {
        /** reserved for app usage */
        uint32_t u32;
        struct __attribute__ ((__packed__)) {
            /** ttl or hopcount field for app usage - 0xff if not used*/
            uint8_t    ttl;
            /** reserved for app usage - 0x00 if not used */
            uint8_t    u8;
            /** reserved for app usage - 0xbeef if not used */
            uint16_t   u16;
        };
    };
    /** header length incl. extensions - in network byte order */
    uint16_t   hlen;
    /** payload length - in network byte order */
    uint16_t   plen;
} dessert_msg_t;

/** local processing struct for dessert_msg */
typedef struct dessert_msg_proc {
    /** 16 bits for local processing flags */
    uint16_t    lflags;
    /** 16 bits reserved */
    uint16_t    lreserved;
    /** DESSERT_LBUF_LEN bytes buffer */
    char        lbuf[DESSERT_LBUF_LEN];
} dessert_msg_proc_t;

/** size of a dessert_msg struct */
#define DESSERT_MSGLEN sizeof(struct dessert_msg)

/** size of a dessert_msg_proc struct */
#define DESSERT_MSGPROCLEN sizeof(struct dessert_msg_proc)

/** maximum frame size to assemble as dessert_msg */
#define DESSERT_MAXFRAMEBUFLEN DESSERT_MAXFRAMELEN

/** size of a dessert_msg buffer */
#define dessert_msg_buflen(x) ((x->flags&DESSERT_FLAG_SPARSE)?(x->hlen+x->plen):(DESSERT_MAXFRAMELEN+DESSERT_MSGPROCLEN))

/** flag for dessert_msg.flags - message len is hlen+plen
  * if not set buffer len is assumed as DESSERT_MAXFRAMELEN + DESSERT_MSGPROCLEN */
#define DESSERT_FLAG_SPARSE 0x1

/** flag for dessert_msg_proc.lflags - l25 src is one of our interfaces */
#define DESSERT_LFLAG_SRC_SELF 0x0002

/** flag for dessert_msg_proc.lflags - l25 dst is multicast address*/
#define DESSERT_LFLAG_DST_MULTICAST 0x0004

/** flag for dessert_msg_proc.lflags - l25 dst is one of our interfaces */
#define DESSERT_LFLAG_DST_SELF 0x0008

/** flag for dessert_msg_proc.lflags - l25 dst is broadcast */
#define DESSERT_LFLAG_DST_BROADCAST 0x0010

/** flag for dessert_msg_proc.lflags - l2 src is one of our interfaces */
#define DESSERT_LFLAG_PREVHOP_SELF 0x0020

/** flag for dessert_msg_proc.lflags - l2 dst is one of our interfaces */
#define DESSERT_LFLAG_NEXTHOP_SELF 0x0040

/** flag for dessert_msg_proc.lflags - l2 dst is broadcast */
#define DESSERT_LFLAG_NEXTHOP_BROADCAST 0x0080


/** a extension record to add to a dessert_msg */
typedef struct __attribute__ ((__packed__)) dessert_ext {
    /** type of the extension 
     * user supplied types must be >= DESSERT_EXT_USER */
    uint8_t    type;            
    
    /** length of the extension in bytes
      * including the 2 bytes of the extension
      * header itself*/
    uint8_t    len;             
    
    /** pointer to the data - real length is len-2 bytes */
    uint8_t       data[DESSERT_MAXEXTDATALEN];    
} dessert_ext_t;


/** length of dessert_ext header */
#define DESSERT_EXTLEN (sizeof(struct dessert_ext) - DESSERT_MAXEXTDATALEN)

/** dessert_ext type wildcard - any extension */
#define DESSERT_EXT_ANY 0x00

/** dessert_ext type for ethernet header */
#define DESSERT_EXT_ETH 0x01

/** dessert_ext type for packet tracing */
#define DESSERT_EXT_TRACE 0x02

/** first dessert_ext type for usage by the user */
#define DESSERT_EXT_USER 0x40

/** packet tracing flag - only record hosts */
#define DESSERT_MSG_TRACE_HOST (ETHER_ADDR_LEN)

/** packet tracing flag - record interfaces */
#define DESSERT_MSG_TRACE_IFACE (3*ETHER_ADDR_LEN)

/** an interface used for dessert_msg frames */
typedef struct dessert_meshif {
    /** pointer to next interface */
    struct dessert_meshif    *next;
    /** name of interface */
    char                if_name[IFNAMSIZ];
    /** system ifindex */
    unsigned int        if_index;
    /** hardware address of interface */
    uint8_t             hwaddr[ETHER_ADDR_LEN];
    /** counter mutex */
    pthread_mutex_t     cnt_mutex;
    /** packet counter in */
    uint64_t            ipkts;
    /** packet counter out */
    uint64_t            opkts;
    /** packet counter in */
    uint64_t            ibytes;
    /** packet counter out */
    uint64_t            obytes;
    /** libpcap descriptor for the interface */
    pcap_t              *pcap;
    /* libpcap error message buffer */
    char                pcap_err[PCAP_ERRBUF_SIZE];
    /** pthread running the request loop */
    pthread_t           worker;
} dessert_meshif_t;



/** a tun/tap interface used to inject packets to dessert implemented daemons
  * please make sure first fields are equal to dessert_meshif to re-use _dessert_meshif_gethwaddr */
typedef struct dessert_tunif {
    /** pointer to next interface */
    struct dessert_tunif   *next;
    /** name of interface */
    char                if_name[IFNAMSIZ];
    /** system ifindex */
    unsigned int        if_index;
    /** hardware address of the interface */
    uint8_t             hwaddr[ETHER_ADDR_LEN];
    /** counter mutex */
    pthread_mutex_t     cnt_mutex;
    /** packet counter in */
    uint64_t            ipkts;
    /** packet counter out */
    uint64_t            opkts;
    /** packet counter in */
    uint64_t            ibytes;
    /** packet counter out */
    uint64_t            obytes;
    /** file descriptor to read/write from/to */
    int                 fd;
    /** if it is a tun or tap interface */
    uint8_t             flags;
    /** pthread running the request loop */
    pthread_t           worker;
} dessert_tunif_t;



/* manipulation routines */
int dessert_msg_new(dessert_msg_t **msgout);
int dessert_msg_ethencap(const struct ether_header* eth, size_t eth_len, dessert_msg_t **msgout);
int dessert_msg_ethdecap(const dessert_msg_t* msg, struct ether_header** ethout);
int dessert_msg_addpayload(dessert_msg_t* msg, void** payload, int len);
int dessert_msg_addext(dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, size_t len);
int dessert_msg_delext(dessert_msg_t *msg, dessert_ext_t *ext);
int dessert_msg_getext(const dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, int index);
#define dessert_ext_getdatalen(ext) (ext->len - DESSERT_EXTLEN)
struct ether_header* dessert_msg_getl25ether (const dessert_msg_t* msg);
int dessert_msg_check(const dessert_msg_t* msg, size_t len);
int dessert_msg_clone(dessert_msg_t **msgnew, const dessert_msg_t *msgold, uint8_t sparse);
int dessert_msg_proc_clone(dessert_msg_proc_t **procnew, const dessert_msg_proc_t *procold);
void dessert_msg_proc_dump(const dessert_msg_t* msg, size_t len, const dessert_msg_proc_t *proc, char *buf, size_t blen);
void dessert_msg_dump(const dessert_msg_t* msg, size_t len, char *buf, size_t blen);
int dessert_msg_trace_initiate(dessert_msg_t* msg, int mode);
int dessert_msg_trace_dump(const dessert_msg_t* msg, char* buf, int blen);
void dessert_msg_destroy(dessert_msg_t* msg);
void dessert_msg_proc_destroy(dessert_msg_proc_t* proc);



/* general routines */
int dessert_logcfg(uint16_t opts);
int dessert_init(const char* proto, int version, uint16_t opts, char* pidfile);
int dessert_run();
void dessert_exit();
dessert_frameid_t dessert_newframeid();

/** flag for dessert_logcfg - enable syslog logging */
#define DESSERT_LOG_SYSLOG    0x0001 

/** flag for dessert_logcfg - disable syslog logging */
#define DESSERT_LOG_NOSYSLOG  0x0002 

/** flag for dessert_logcfg - enable logfile logging 
 * before using this you MUST use fopen(dessert_logfd, ...) to open the logfile */
#define DESSERT_LOG_FILE      0x0004 

/** flag for dessert_logcfg - disable logfile logging */
#define DESSERT_LOG_NOFILE    0x0008 

/** flag for dessert_logcfg - enable logging to stderr */
#define DESSERT_LOG_STDERR    0x0010 

/** flag for dessert_logcfg - disable logging to stderr */
#define DESSERT_LOG_NOSTDERR  0x0020 

/** flag for dessert_logcfg - enable logging to ringbuffer */
#define DESSERT_LOG_RBUF      0x0040 

/** flag for dessert_logcfg - disable logging to ringbuffer */
#define DESSERT_LOG_NORBUF    0x0080 

/** flag for dessert_logcfg - enable debug loglevel */
#define DESSERT_LOG_DEBUG        0x0100 

/** flag for dessert_logcfg - disable debug loglevel */
#define DESSERT_LOG_NODEBUG      0x0200 

/** flag for dessert_init - daemonize when calling
 * disables logging to STDERR */
#define DESSERT_OPT_DAEMONIZE    0x0100 

/** flag for dessert_init - do not daemonize when calling */
#define DESSERT_OPT_NODAEMONIZE  0x0200 

/** flag for dessert_init - create and write pid file */
#define DESSERT_OPT_PID			0x0400

/** flag for dessert_init - do not create and write pid file */
#define DESSERT_OPT_NOPID		0x0800

/** global status flag holder */
extern int         _dessert_status;

/** flag for _dessert_status - program is daemon */
#define _DESSERT_STATUS_DAEMON   0x1


void _dessert_log(int level, const char* func, const char* file, int line, const char *fmt, ...);
#define dessert_debug(...) _dessert_log(LOG_DEBUG, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_info(...) _dessert_log(LOG_INFO, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_notice(...) _dessert_log(LOG_NOTICE, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_warn(...) _dessert_log(LOG_WARNING, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_warning(...) _dessert_log(LOG_WARNING, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_err(...) _dessert_log(LOG_ERR, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_crit(...) _dessert_log(LOG_CRIT, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_alert(...) _dessert_log(LOG_ALERT, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define dessert_emerg(...) _dessert_log(LOG_EMERG, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)



/* tun/tap handling */
int dessert_tunif_init(char* name, uint8_t flags);

 /** flag for dessert_tunif_init - open tun (ip/ipv6) device */
#define DESSERT_TUN          0x00   

/** flag for dessert_tunif_init - open tap (ethernet) device */
#define DESSERT_TAP          0x01    

/** flag for dessert_tunif_init - set dessert_l25_defsrc to mac of tap device */
#define DESSERT_MAKE_DEFSRC  0x02    

/** flag for dessert_tunif_init - get mac for tap failed - try mac in src of first packet */
#define _DESSERT_TAP_NOMAC   0x80    



/** callback type to call if a packed should be injected into dessert via a tun/tap interface
 *
 * The callbacks are invoked with no locks hold by the thread,
 * YOU MUST make sure the thread holds no locks after the callback exits.
 * YOU MUST also make sure not to do anything blocking in a callback!
 * 
 * @arg *eth ethernet frame received (ether_[sd]host is null when tun if is used)
 * @arg len length of ethernet frame received
 * @arg *proc local processing buffer passed along the callback pipeline - may be NULL
 * @arg *tunif interface received packet on
 * @arg id unique internal frame id of the packet
 * ®return DESSERT_MSG_KEEP to continue processing the packet, DESSERT_MSG_DROP to drop it
*/
typedef int dessert_tunrxcb_t(struct ether_header *eth, size_t len, dessert_msg_proc_t *proc, dessert_tunif_t *tunif, dessert_frameid_t id);

int dessert_tunrxcb_add(dessert_tunrxcb_t* c, int prio);
int dessert_tunrxcb_del(dessert_tunrxcb_t* c);

/** callback list entry for tun/tap callbacks */
typedef struct dessert_tunrxcbe {
    /** pointer to callback to call */
    dessert_tunrxcb_t    *c;
    /** priority - lowest first */
    int                     prio;
    /** next entry in list */
    struct dessert_tunrxcbe    *next;
} dessert_tunrxcbe_t;

int dessert_tunsend(const struct ether_header *eth, size_t len);



/* interface handling */

/** flag for dessert_meshif_add - set interface in promiscuous-mode (default) */
#define DESSERT_IF_PROMISC 0x0

/** flag for dessert_meshif_add - do not set interface in promiscuous-mode */
#define DESSERT_IF_NOPROMISC 0x1

/** flag for dessert_meshif_add - filter out non-des-sert frames in libpcap (default) */
#define DESSERT_IF_FILTER 0x0

/** flag for dessert_meshif_add - do not filter out non-des-sert frames in libpcap */
#define DESSERT_IF_NOFILTER 0x2

int dessert_meshif_add(const char* dev, uint8_t flags);
struct dessert_meshif* dessert_meshif_get(const char* dev);
int _dessert_meshif_gethwaddr(dessert_meshif_t *despif);



/* send packet */
int dessert_meshsend(const dessert_msg_t* msg, const dessert_meshif_t *iface);
int dessert_meshsend_fast(dessert_msg_t* msg, const dessert_meshif_t *iface);
int dessert_meshsend_raw(dessert_msg_t* msg, const dessert_meshif_t *iface); 

/** callbacks type to call if a packed are received via a dessert interface
 *
 * The callbacks are invoked with no locks hold by the thread,
 * YOU MUST make sure the thread holds no locks after the callback exits.
 * YOU MUST also make sure not to do anything blocking in a callback!
 *
 * If the callback exits with DESSERT_MSG_NEEDMSGPROC or DESSERT_MSG_NEEDNOSPARSE
 * and the respective buffer is NULL or sparse, the callback is called again after
 * providing the requested resource
 *
 * @arg *msg dessert_msg_t frame received
 * @arg len length of the buffer pointed to from dessert_msg_t
 * @arg *proc local processing buffer passed along the callback pipeline - may be NULL
 * @arg *iface interface received packet on - may be NULL
 * @arg id unique internal frame id of the packet
 * @return DESSERT_MSG_KEEP to continue processing the packet
 * @return DESSERT_MSG_DROP to drop it
 * @return DESSERT_MSG_NEEDMSGPROC to get a processing buffer
 * @return DESSERT_MSG_NEEDNOSPARSE to get a full packet buffer (e.g. needed to add extensions)
 */
typedef int dessert_meshrxcb_t(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

/** callback list entry for dessert interface callbacks */
typedef struct dessert_meshrxcbe {
    /** pointer to callback to call */
    dessert_meshrxcb_t   *c;
    /** priority - lowest first */
    int                     prio;
    /** next entry in list */
    struct dessert_meshrxcbe   *next;
} dessert_meshrxcbe_t;

int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio);
int dessert_meshrxcb_del(dessert_meshrxcb_t* c);
int dessert_meshrxcb_runall(dessert_msg_t* msg_in, size_t len, dessert_msg_proc_t *proc_in, const dessert_meshif_t *despif, dessert_frameid_t id);



/* helper callbacks */
int dessert_msg_dump_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_check_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_ifaceflags_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *riface, dessert_frameid_t id);
int dessert_msg_trace_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);


/* cli */
int _dessert_cli_init();
int dessert_cli_run(int port);
extern struct cli_def *dessert_cli;
extern struct cli_command *dessert_cli_show;
extern struct cli_command *dessert_cli_cfg_iface;
extern struct cli_command *dessert_cli_cfg_no;
extern struct cli_command *dessert_cli_cfg_no_iface;
extern struct cli_command *dessert_cli_cfg_set;
extern struct cli_command *dessert_cli_cfg_logging;
extern struct cli_command *dessert_cli_cfg_no_logging;


/* periodic */
/** callbacks type to call in a periodic task
 *
 * The callbacks are invoked with no locks hold by the thread,
 * YOU MUST make sure the thread holds no locks after the callback exits.
 * YOU MUST also make sure not to do anything blocking in a callback!
 *
 * @arg *data void pointer to pass to the callback
 * @arg scheduled when this call was scheduled
 * @arg interval how often this call should be scheduled
 * ®return should be 0, otherwise the callback is unregistered
 */
typedef int dessert_periodiccallback_t(void *data, struct timeval *scheduled, struct timeval *interval);

/** definition of a periodic tasklist entry */
typedef struct dessert_periodic {
    /** callback to call */
    dessert_periodiccallback_t *c;
    /** when to call next */
    struct timeval scheduled;
    /** call every */
    struct timeval interval;
    /** data pointer to pass to callback */
    void *data;
    /** internal pointer for task list */
    struct dessert_periodic  *next;
} dessert_periodic_t;


dessert_periodic_t *dessert_periodic_add(dessert_periodiccallback_t* c, void *data, const struct timeval *scheduled, const struct timeval *interval);
dessert_periodic_t *dessert_periodic_add_delayed(dessert_periodiccallback_t* c, void *data, int delay);
int dessert_periodic_del(dessert_periodic_t *p);
void _dessert_periodic_init();


#define likely(x)       (__builtin_expect((x),1))
#define unlikely(x)     (__builtin_expect((x),0))

#define __dessert_assert(func, file, line, e) \
    ((void)_dessert_log(LOG_EMERG, func, file, line, "assertion `%s' failed!\n", e), abort)

#ifdef NDEBUG
#define assert(e)       ((void)0)
#else
#define assert(e) \
    (__builtin_expect(!(e), 0) ? __dessert_assert(__FUNCTION__, __FILE__, __LINE__, #e) : (void)0)
#endif

#endif
