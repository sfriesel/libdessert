/***************************************************************************//**
 @file

 @page license License

 @brief Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).     \n
 All rights reserved.                                                         \n
 
 These sources were originally developed by Philipp Schmidt
 and modified by David Gutzmann and Bastian Blywis
 at Freie Universitaet Berlin (http://www.fu-berlin.de/),
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group  \n
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)                   \n
 -----------------------------------------------------------------------------\n
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.                                                                     \n
 \n
 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n
 \n
 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .                     \n
 -----------------------------------------------------------------------------\n
 For further information and questions please use the web site                \n
        http://www.des-testbed.net/
*******************************************************************************/

/***************************************************************************//**
 *
 * @mainpage DES-SERT
 *
 *  \image html dessert.png "DES-SERT"
 *  \image latex dessert.eps "DES-SERT" width=.7\linewidth
 *
 * @section intro_sec Introduction
 *
 * DES-SERT, the DES Simple and Extensible Routing-Framework for Testbeds,
 * is a framework designed to assist researchers in the implementation of
 * routing protocols for testbeds.
 *
 * DES-SERT enables the implementation of routing protocols on top of
 * Ethernet via an underlay (Layer 2.5) in user space; this also includes
 * IEEE 802.11 on the data link layer.
 * It introduces an abstraction from OS specific issues and provides
 * functionality and data structures to implement proactive, reactive,
 * and hybrid routing protocols.

 * While generally usable in many application scenarios, it is primarily
 * used in DES-Mesh (http://www.des-testbed.net/), the multi-transceiver
 * wireless mesh network testbed part of the DES-Testbed at Freie 
 * Universitaet Berlin, Germany.
 *
 * @section dessert_sec DES-SERT
 *
 * DES-SERT introduces several concepts to implement routing protocols.
 * When implementing a routing protocol with DES-SERT, you should be
 * familiar with these concepts to achieve an optimal structure and 
 * to make your implementation easier to understand by other developers.
 *
 * @section arch_sec System Architecture
 *
 * DES-SERT uses <a href="http://www.tcpdump.org/">libpcap</a> to receive packets 
 * from network interfaces. User space generated packets are received via 
 * a TUN or TAP interface which the kernel provides for routing
 * daemons based on DES-SERT.
 *
 *  \image html lib-kernel-if.png "DES-SERT System Architecture"
 *  \image latex lib-kernel-if.eps "DES-SERT System Architecture" width=.7\linewidth
 *
 * @subsection messages_subsec DES-SERT Messages
 *
 * Every packet you send or receive is represented as a
 * DES-SERT message. From a programmers point of view, a DES-SERT message
 * is just a C-structure:
 *
 * @code
 *  typedef struct __attribute__ ((__packed__)) dessert_msg {
 *      struct     ether_header l2h;
 *      char       proto[DESSERT_PROTO_STRLEN];
 *      uint8_t    ver;
 *      uint8_t    flags;
 *      union {
 *          uint32_t u32;
 *          struct __attribute__ ((__packed__)) {
 *              uint8_t    ttl;
 *              uint8_t    u8;
 *              uint16_t   u16;
 *          };
 *      };
 *      uint16_t   hlen;
 *      uint16_t   plen;
 *  } dessert_msg_t;
 * @endcode
 *
 * Every message sent via the underlay carries this structure as a packet
 * header. All data in a dessert_msg_t is stored in network byte order.
 * DES-SERT tries to take care of this structure as much as possible.
 * Developers have to only provide a value for the destination in the 
 * Ethernet header (ether_dhost) in dessert_msg_t.l2h.
 *
 * If you need to send some management data with a packet, e.g. some kind of
 * metric value your routing protocol uses, you should try to fit this
 * data into the "u8" or "u16" field.
 * These fields will never be modified by DES-SERT except on initialization
 * via dessert_msg_new(). the "ttl" field shoud be used to implement a time-to-live
 * functionality to limit the forwarding of packets to a particular number of
 * hops. If you do not need such a feature, you can use the dessert_msg_t.ttl field for other
 * tasks.
 *
 * dessert_msg_t is just a simple C-structure but there are several 
 * utility functions available - please have a look at "dessert.h" and the
 * doxygen documentation. The most important ones are: dessert_msg_new() and
 * dessert_msg_destroy(). The first one allocates memory for a DES-SERT 
 * message including space for payload and extensions and initializes the
 * structure. The latter function destroys the DES-SERT message and frees the
 * memory. For normal data packets or received management packets you usually never 
 * need to create or destroy DES-SERT messages as the framework will handle these tasks.
 * You just need to use the functions when sending management packets, e.g., in some
 * specific interval. Last but not least, the dessert_msg_clone() function is provided which
 * creates a copy of the message including extensions and payload.
 *
 *  @code
 *  int dessert_msg_new(dessert_msg_t **msgout);
 *
 *  int dessert_msg_clone(dessert_msg_t **msgnew, const dessert_msg_t *msgold, uint8_t sparse);
 *
 *  void dessert_msg_destroy(dessert_msg_t* msg);
 * @endcode
 *
 *
 * @subsection extensions_subsec DES-SERT Extensions
 *
 * A DES-SERT extension is data piggybacked on a DES-SERT message.
 * The corresponding C-structure consists of a 8-bit user supplied type field, 
 * an 8-bit length field and user supplied data (up to 253 bytes). Extensions
 * are thus type-length-value (TLV) elements and similar to what RFC 5444 tries
 * to provide.
 *
 * @code
 *  typedef struct __attribute__ ((__packed__)) dessert_ext {
 *    uint8_t    type;
 *    uint8_t    len;
 *    uint8_t       data[DESSERT_MAXEXTDATALEN];
 *  } dessert_ext_t;
 * @endcode
 *
 * Extensions can be added to a DES-SERT message via dessert_msg_addext(), 
 * retrieved via dessert_msg_getext() and removed via dessert_msg_delext().
 *
 * @code
 *  int dessert_msg_addext(dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, size_t len);
 *
 *  int dessert_msg_delext(dessert_msg_t *msg, dessert_ext_t *ext);
 *
 *  int dessert_msg_getext(const dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, int index);
 *
 * @endcode
 *
 * It is recommended not to put single data fields in extensions, but
 * combine semantically related data in a struct and attach this struct
 * as an extension because every extension introduces 16-bit overhead 
 * to the packet.
 *
 * The extension feature of DES-SERT can be used to add, modify, and delete
 * arbitrary data in a straight forward and easy way. You should try to
 * piggyback as much management data onto data packets to reduce the 
 * data traffic on the medium. Whatever information an extension will provide
 * is entirely up to you: MPLS-like labels, topology information, urgent information, ...
 *
 *  \image html piggybacking.png "Piggybacking of extensions in DES-SERT messages"
 *  \image latex piggybacking.eps "Piggybacking of extensions in DES-SERT messages" width=.6\linewidth
 *
 *
 * @subsection pipelines_subsec Processing Pipelines
 *
 * Routing algorithms are often split up in several parts like packet
 * validation, loop-detection or routing table lookup.
 * To implement these as independent and clear as possible, DES-SERT enables
 * you to split up your packet processing in as many parts as you like.
 *
 * There are two separate processing pipelines - one for packets received
 * from the kernel via a TUN or TAP interface (see ::dessert_sysif_t) and 
 * one for packets received via an interface used on the mesh network
 * (see ::dessert_meshif_t).
 *
 *  \image html pipelining.png "Pipelining in DES-SERT daemons"
 *  \image latex pipelining.eps "Pipelining in DES-SERT daemons" width=.6\linewidth
 *
 * You can register callback functions at these pipelines with
 * dessert_sysrxcb_add() or dessert_meshrxcb_add(). Both take an additional
 * integer argument ("priority") specifying the order the callbacks should
 * be called. Lower values represent a higher priority and thus an earlier position in
 * the pipeline. Thus a callback function represents a stage of a pipeline.
 *
 * @code
 *  int dessert_sysrxcb_add(dessert_sysrxcb_t* c, int prio);
 *  int dessert_sysrxcb_del(dessert_sysrxcb_t* c);
 *
 *  int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio);
 *  int dessert_meshrxcb_del(dessert_meshrxcb_t* c);
 * @endcode
 *
 * If a callback returns #DESSERT_MSG_KEEP the packed will be processed by
 * further callbacks, if it returns #DESSERT_MSG_DROP the message will be
 * dropped and no further callbacks will be called. In the latter case,
 * DES-SERT will free the memory.
 *
 * @subsection sparse_subsec Message Size Management
 *
 * When packets (IP datagrams or Ethernet frames) are received from user space,
 * they are automatically encapsulated in a DES-SERT message. The allocated memory
 * is of maximum size so that you can start to add extensions.
 *
 * Packets received from the network will probably have a smaller size and are
 * called "sparse" messages. If you need to add extensions or enlarge the payload 
 * of a message, you need to tell DES-SERT to enlarge the buffer for you. In sparse messages
 * the flag #DESSERT_FLAG_SPARSE is set. The buffer will be automatically 
 * enlarged by returning #DESSERT_MSG_NEEDNOSPARSE from the callback. After DES-SERT has
 * reallocated the memory the callback will be called again and the #DESSERT_FLAG_SPARSE 
 * will not be set anymore.
 *
 * @code
 *   if (proc->lflags & DESSERT_FLAG_SPARSE) {
 *       return DESSERT_MSG_NEEDNOSPARSE;
 *   }
 * @endcode
 *
 *
 * @subsection buffer_subsec Processing Buffer
 *
 * If you need to pass information along several callbacks in a pipeline, you can
 * use the processing buffer passed as parameter to the callbacks. This buffer contains
 * local processing flags ("lflags") set by the builtin callback dessert_msg_ifaceflags_cb()
 * (e.g. marking multicast messages or if you received a message sent by yourself due to a loop)
 * and 1KB space to pass along arbitrary data.
 *
 * @code
 *  typedef struct dessert_msg_proc {
 *      uint16_t    lflags;
 *      uint16_t    lreserved;
 *      char        lbuf[DESSERT_LBUF_LEN];
 *  } dessert_msg_proc_t;
 * @endcode
 *
 * This buffer is only be allocated after you explicitly request it. If the proc parameter
 * of a callback function is NULL, you can return the value
 * #DESSERT_MSG_NEEDMSGPROC to let DES-SERT automatically create the processing buffer.
 * The callback will be called again afterwards.
 *
 * @code
 *   if (proc == NULL) {
 *       return DESSERT_MSG_NEEDMSGPROC;
 *   }
 * @endcode
 *
 * The processing buffer can be cloned or destroyed if required.
 *
 * @code
 *  int dessert_msg_proc_clone(dessert_msg_proc_t **procnew, const dessert_msg_proc_t *procold);
 *  
 *  void dessert_msg_proc_destroy(dessert_msg_proc_t* proc);
 * @endcode
 *
 * Always remember that the processing buffer is only used for local processing. It is not 
 * part of the DES-SERT message and therefore will never be sent over the network.
 *
 * @section interfaces_sec Interfaces
 *
 * @subsection sysif_subsec Interfacing with the Kernel and User Space
 *
 * When developing a daemon you have to choose whether you like to use a TUN or 
 * TAP device to receive packets from user space. Packets received or sent via a TUN interface 
 * are IPv4/IPv6 datagrams; packets received or sent via TAP devices are Ethernet frames.
 * If you intend to implement a custom layer 2 to layer 3 mapping and minimize the overhead,
 * you should use a TUN interface.
 * 
 * Currently, you can only use a single sys respectively TUN/TAP interface.
 * The function dessert_sysif_init() enables to create the particular sys interface.
 * You must then set up the interface by calling "ifconfig".
 *
 * Please note that DES-SERT also provides a CLI callback for this task and that you
 * do not have to implement this feature yourself.
 *
 * @code
 *  int dessert_sysif_init(argv[0], DESSERT_TAP | DESSERT_MAKE_DEFSRC);
 *  sprintf(buf, "ifconfig %s %s netmask %s mtu 1300 up", argv[0], argv[1], argv[2]);
 *  i = system(buf);
 * @endcode
 *
 * Packets received from the TUN/TAP interface will be
 * passed along the callbacks added by dessert_sysrxcb_add to the sys pipeline.
 * Each callack function will be called with a pointer to the DES-SERT message containing
 * the received data from layer 3 upwards as payload. In the case of a TAP interface, the 
 * data from the Ethernet header is copied into a DES-SERT Ethernet extension.
 *
 * Packets are sent to the user space via the kernel network stack with dessert_syssend.
 * Your lowest priority callback in the sys pipeline should always send packets to the
 * user space if the DES-SERT message was not dropped by higher priority callbacks. Even
 * when you make a mistake and the packet is not for this host, the kernel will probably drop
 * it for you.
 *
 * @code
 *  int dessert_syssend_msg(dessert_msg_t *msg);
 * @endcode
 *
 *
 * @subsection meshif_subsec Sending and Receiving Packets from the Network
 *
 * Mesh interfaces are used similar to the TUN/TAP interface with two major
 * differences: You can have multiple mesh interfaces and they send and
 * receive DES-SERT messages instead of Ethernet frames or IP datagrams.
 *
 * A mesh interface is added by dessert_meshif_add() and can be used to send 
 * DES-SERT messages with dessert_meshsend(). If the interface parameter is NULL, the
 * packet will be transmitted over every registered mesh interface (good for flooding).
 *
 * There are several functions to send DES-SERT messages. For further information please
 * refer to their descriptions.
 *
 * @code
 *  int dessert_meshif_add(const char* dev, uint8_t flags);
 *
 *  int dessert_meshsend(const dessert_msg_t* msgin, const dessert_meshif_t *iface);
 *
 *  int dessert_meshsend_hwaddr(const dessert_msg_t* msgin, const uint8_t hwaddr[ETHER_ADDR_LEN]);
 *
 *  int dessert_meshsend_allbutone(const dessert_msg_t* msgin, const dessert_meshif_t *iface);
 *
 *  int dessert_meshsend_fast(dessert_msg_t* msg, const dessert_meshif_t *iface);
 *
 *  int dessert_meshsend_fast_hwaddr(dessert_msg_t* msg, const uint8_t hwaddr[ETHER_ADDR_LEN]);
 *
 *  int dessert_meshsend_fast_allbutone(dessert_msg_t* msg, const dessert_meshif_t *iface);
 *
 *  int dessert_meshsend_raw(dessert_msg_t* msg, const dessert_meshif_t *iface);
 * @endcode
 *
 * @section logging_sec Logging
 *
 * Log messages can be written by a bunch of macros: #dessert_debug, #dessert_info, 
 * #dessert_notice, #dessert_warn, #dessert_warning, #dessert_err, #dessert_crit,
 * #dessert_alert and #dessert_emerg. Each macro can be used like "printf" supporting 
 * the same syntax. The log messages can be written to Syslog, STDERR, a file or ringbuffer
 * depending on your configuration
 *
 * @code
 *  dessert_logcfg(DESSERT_LOG_DEBUG | DESSERT_LOG_NOSTDERR | DESSERT_LOG_SYSLOG | DESSERT_LOG_RBUF | DESSERT_LOG_FILE);
 * @endcode
 *
 * DES-SERT also ships with a custom #assert macro which acts like
 * the original macro from the standard C library and uses the logging
 * mechanism described above.
 *
 *
 * @section periodics_sec Periodics
 *
 * Periodics help you to perform maintenance or delayed tasks. A task
 * consists of a callback, which will be called at the time you requested.
 * The callback will be passed a void pointer to data that you specified at 
 * registration time. You can add tasks by calling dessert_periodic_add() or
 * dessert_periodic_add_delayed() or delete registered callbacks with dessert_periodic_del().
 * The data pointer may be NULL and you can optionally specify when the callback should
 * be called for the first time.
 *
 * @code
 *  uint16_t data = 0;
 *  struct timeval my_interval;
 *  my_interval.tv_sec = 2;
 *  my_interval.tv_usec = 0;
 *  dessert_periodic_add(my_periodic_function, &data, NULL, &my_interval);
 *  ...
 *  dessert_periodic_add(my_periodic_function);
 * @endcode
 *
 *
 * @section cli_sec Command Line Interface
 *
 * DES-SERT supports simple configuration and debugging of your routing
 * daemons by providing a Cisco like command line interface (CLI) and a config 
 * file parser based upon it.
 * The CLI is implemented based on <a href="http://code.google.com/p/libcli/">libcli</a>.
 *
 * DES-SERT does some basic initialization of the CLI provided by libcli.
 * The main CLI anchor dessert_cli and some anchors to add commands below in
 * the hierarchy "dessert_cli_.*". Because DES-SERT only loosely wraps libcli,
 * you should make yourself familiar with libcli.
 *
 * The command line interface is available via telnet on a specified port and 
 * started with dessert_cli_run().
 *
 * @subsection cli_conf_sec Daemon Configuration
 *
 * The daemon configuration makes also use of the CLI. Daemons are usually started with a
 * single parameter: the path and file name of the configuration file.
 * You can get a pointer configuration file with dessert_cli_get_cfg(). The function will
 * first try open the file specified as parameter and if this fails tries to open the
 * file /etc/DAEMON_NAME.conf. Give the returned FILE pointer to cli_file() which is provided 
 * by libcli to parse the configuration.
 *
 * @code
 *  FILE *cfg = dessert_cli_get_cfg(argc, argv);
 *  assert(cfg);
 *  ...
 *  cli_file(dessert_cli, cfg, PRIVILEGE_PRIVILEGED, MODE_CONFIG);
 *  dessert_cli_run();
 * @endcode
 *
 * @section all_sec  Putting it all together
 *
 * Now you have learned about the most important aspects of DES-SERT.
 * To write your own routing protocol implementation, you need to know
 * how to put all this together.
 *
 * You should start with a main() program parsing the command line options
 * and then calling "dessert_init()". This is needed to set up DES-SERT
 * correctly. Afterwards you can register callbacks, read the config file
 * and do what you like. If everything is set up, you call "dessert_run()"
 * and let the event based framework do its job.
 *
 * If you would like to see a complete protocol implementation sample,
 * have a look at the "gossiping" directory.
 *
 *
 * @section feedback_sec Contact & Feedback
 *
 * We love feedback - if you have patches, comments or questions,
 * please contact us! Recent contact information is available on
 *         http://www.des-testbed.net/des-sert/
 *
 ******************************************************************************/

#ifndef DESSERT_H
#define DESSERT_H

#ifdef __DARWIN__
#include <net/if_dl.h>
#define TUN_BSD
#endif

#ifdef __linux__
#define TUN_LINUX
#endif

#include <net/if.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdint.h>
#include <syslog.h>
#include <stdlib.h>
#include <libcli.h>

/***************************************************************************//**
 *
 * @defgroup global G L O B A L   # D E F I N E S   and   T Y P E D E F S   /   S T R U C T U R E S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

/** ethernet protocol used on layer 2 */
#define DESSERT_ETHPROTO 0x8042

/** maximum frame size to assemble as dessert_msg */
#define DESSERT_MAXFRAMELEN ETHER_MAX_LEN

/** maximum size of the data part in dessert_ext */
#define DESSERT_MAXEXTDATALEN 253

/** length of protocol string used in dessert_msg */
#define DESSERT_PROTO_STRLEN 4

/** size of local message processing buffer */
#define DESSERT_LBUF_LEN 1024

/** return code for many dessert_* functions */
#define DESSERT_OK                  0

/** return code for many dessert_* functions */
#define DESSERT_ERR                 1

/******************************************************************************
 * typedefs
 ******************************************************************************/
/** runtime-unique frame id */
typedef uint64_t dessert_frameid_t;

/** A basic message send on des-sert layer2.5. */
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

/** local processing struct for dessert_msg_t */
typedef struct dessert_msg_proc {
    /** 16 bits for local processing flags */
    uint16_t    lflags;
    /** 16 bits reserved */
    uint16_t    lreserved;
    /** DESSERT_LBUF_LEN bytes buffer */
    char        lbuf[DESSERT_LBUF_LEN];
} dessert_msg_proc_t;

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

/** an interface used for dessert_msg frames */
typedef struct dessert_meshif {
    /** pointer to next interface */
    struct dessert_meshif    *next;
    /** name of interface */
    char                if_name[IFNAMSIZ];
    /** system ifindex */
    unsigned int        if_index;
    /** hardware address of interface */
    uint8_t             hwaddr[ETHER_ADDR_LEN]; /* uthash key*/
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
    /** libpcap error message buffer */
    char                pcap_err[PCAP_ERRBUF_SIZE];
    /** pthread running the request loop */
    pthread_t           worker;

    /** pointer to prev interface */
    struct dessert_meshif    *prev;
} dessert_meshif_t;

/** A tun/tap interface used to inject packets to dessert implemented daemons.
 *
 * \note Please make sure first fields are equal to dessert_meshif to re-use
 * _dessert_meshif_gethwaddr().
 *
 */
typedef struct dessert_sysif {
    /** pointer to next interface */
    struct dessert_sysif   *next;
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
} dessert_sysif_t;

/** Callback type to call if a packed is received via a dessert mesh interface.
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *iface interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_KEEP to continue processing the packet
 * @retval DESSERT_MSG_DROP to drop it
 * @retval DESSERT_MSG_NEEDMSGPROC to get a processing buffer
 * @retval DESSERT_MSG_NEEDNOSPARSE to get a full packet buffer (e.g. needed to add extensions)
 *
 * \warning The callbacks are invoked with no locks hold by the thread,
 * \warning YOU MUST make sure the thread holds no locks after the callback exits.
 * \warning YOU MUST also make sure not to do anything blocking in a callback!
 *
 * If the callback exits with DESSERT_MSG_NEEDMSGPROC or DESSERT_MSG_NEEDNOSPARSE
 * and the respective buffer is NULL or sparse, the callback is called again after
 * providing the requested resource.
 *
 */
typedef int dessert_meshrxcb_t(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

/** Callback type to call if a packed should be injected into dessert via a tun/tap interface.
 *
 * @param *msg dessert msg received - original ethernet frame is encapsulated within
 * @param len length of ethernet frame received
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *sysif interface received packet on
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_KEEP to continue processing the packet
 * @retval DESSERT_MSG_DROP to drop it
 *
 * \warning The callbacks are invoked with no locks hold by the thread,
 * \warning YOU MUST make sure the thread holds no locks after the callback exits.
 * \warning YOU MUST also make sure not to do anything blocking in a callback!
 *
*/
typedef int dessert_sysrxcb_t(dessert_msg_t *msg, size_t len, dessert_msg_proc_t *proc, dessert_sysif_t *sysif, dessert_frameid_t id);

/** callbacks type to call in a periodic task
 *
 * The callbacks are invoked with no locks hold by the thread,
 * YOU MUST make sure the thread holds no locks after the callback exits.
 * YOU MUST also make sure not to do anything blocking in a callback!
 *
 * @arg *data void pointer to pass to the callback
 * @arg scheduled when this call was scheduled
 * @arg interval how often this call should be scheduled
 * @return should be 0, otherwise the callback is unregistered
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

/***************************************************************************//**
 * @}
 *
 * @defgroup core C O R E
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 *  #defines
 ******************************************************************************/

/** type for local unique packet identification */
#define DESSERT_FRAMEID_MAX ((uint64_t)-1)

/** flag for dessert_init - daemonize when calling
 * disables logging to STDERR */
#define DESSERT_OPT_DAEMONIZE    0x0100

/** flag for dessert_init - do not daemonize when calling */
#define DESSERT_OPT_NODAEMONIZE  0x0200

/******************************************************************************
 * globals
 ******************************************************************************/

/** protocol string used in dessert_msg frames */
extern char        dessert_proto[DESSERT_PROTO_STRLEN+1];

/** version int used in dessert_msg frames */
extern u_int8_t    dessert_ver;

/** default src address used for local generated dessert_msg frames */
extern u_int8_t    dessert_l25_defsrc[ETHER_ADDR_LEN];


/** constant holding ethernet broadcast address after dessert_init */
extern u_char      ether_broadcast[ETHER_ADDR_LEN];

/** constant holding ethernet null address after dessert_init */
extern u_char      ether_null[ETHER_ADDR_LEN];

/** the config funnel */
extern pthread_rwlock_t dessert_cfglock;

/******************************************************************************
 * functions
 ******************************************************************************/

int dessert_init(const char* proto, int version, uint16_t opts);
int dessert_pid(char* pidfile);
int dessert_run(void);
void dessert_exit(void);

/***************************************************************************//**
 * @}
 *
 * @defgroup cli C L I   -   C O M M A N D  _  L I N E  _  I N T E R F A C E
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * globals
 ******************************************************************************/

extern struct cli_def *dessert_cli;

extern struct cli_command *dessert_cli_show;
extern struct cli_command *dessert_cli_cfg_iface;
extern struct cli_command *dessert_cli_cfg_no;
extern struct cli_command *dessert_cli_cfg_no_iface;
extern struct cli_command *dessert_cli_cfg_set;
extern struct cli_command *dessert_cli_cfg_logging;
extern struct cli_command *dessert_cli_cfg_no_logging;

/******************************************************************************
 * functions
 ******************************************************************************/

int dessert_cli_run(void);
FILE* dessert_cli_get_cfg(int argc, char** argv);
int dessert_set_cli_port(uint16_t port);

/***************************************************************************//**
 * @}
 *
 * @defgroup log L O G  _  F A C I L I T Y
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

/** flag for dessert_logcfg - enable syslog logging */
#define DESSERT_LOG_SYSLOG    0x0001

/** flag for dessert_logcfg - disable syslog logging */
#define DESSERT_LOG_NOSYSLOG  0x0002

/** flag for dessert_logcfg - enable logfile logging
 * @warning  before using this you MUST use fopen(dessert_logfd, ...) to open the logfile
 */
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
#define DESSERT_LOG_DEBUG     0x0100

/** flag for dessert_logcfg - disable debug loglevel */
#define DESSERT_LOG_NODEBUG   0x0200

/******************************************************************************
 * functions
 ******************************************************************************/
int dessert_logcfg(uint16_t opts);
void _dessert_log(int level, const char* func, const char* file, int line, const char *fmt, ...);
/** log at DEBUG level */
#define dessert_debug(...) _dessert_log(LOG_DEBUG, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at INFO level */
#define dessert_info(...) _dessert_log(LOG_INFO, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at NOTICE level */
#define dessert_notice(...) _dessert_log(LOG_NOTICE, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at WARNING level */
#define dessert_warn(...) _dessert_log(LOG_WARNING, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at WARNING level */
#define dessert_warning(...) _dessert_log(LOG_WARNING, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at ERR level */
#define dessert_err(...) _dessert_log(LOG_ERR, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at CRIT level */
#define dessert_crit(...) _dessert_log(LOG_CRIT, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at ALERT level */
#define dessert_alert(...) _dessert_log(LOG_ALERT, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
/** log at EMERG level */
#define dessert_emerg(...) _dessert_log(LOG_EMERG, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

/***************************************************************************//**
 * @}
 *
 * @defgroup mesh M E S H   -   I N T E R F A C E S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

/** return code for dessert_meshrxcb_t - forces to copy the message and call again*/
#define DESSERT_MSG_NEEDNOSPARSE     1

/** return code for dessert_meshrxcb_t - forces to generate processing info and call again*/
#define DESSERT_MSG_NEEDMSGPROC      2

/** return code for dessert_meshrxcb_t and dessert_sysrxcb_t */
#define DESSERT_MSG_KEEP             0

/** return code for dessert_meshrxcb_t and dessert_sysrxcb_t */
#define DESSERT_MSG_DROP             -1

/** flag for dessert_meshif_add - set interface in promiscuous-mode (default) */
#define DESSERT_IF_PROMISC 0x0

/** flag for dessert_meshif_add - do not set interface in promiscuous-mode */
#define DESSERT_IF_NOPROMISC 0x1

/** flag for dessert_meshif_add - filter out non-des-sert frames in libpcap (default) */
#define DESSERT_IF_FILTER 0x0

/** flag for dessert_meshif_add - do not filter out non-des-sert frames in libpcap */
#define DESSERT_IF_NOFILTER 0x2

/******************************************************************************
 * functions
 ******************************************************************************/

/* sending messages */
int dessert_meshsend(const dessert_msg_t* msgin, const dessert_meshif_t *iface);
int dessert_meshsend_allbutone(const dessert_msg_t* msgin, const dessert_meshif_t *iface);
int dessert_meshsend_hwaddr(const dessert_msg_t* msgin, const uint8_t hwaddr[ETHER_ADDR_LEN]);
int dessert_meshsend_randomized(const dessert_msg_t* msgin);

int dessert_meshsend_fast(dessert_msg_t* msg, const dessert_meshif_t *iface);
int dessert_meshsend_fast_allbutone(dessert_msg_t* msg, const dessert_meshif_t *iface);
int dessert_meshsend_fast_hwaddr(dessert_msg_t* msg, const uint8_t hwaddr[ETHER_ADDR_LEN]);
int dessert_meshsend_fast_randomized(dessert_msg_t* msgin);
int dessert_meshsend_raw(dessert_msg_t* msg, const dessert_meshif_t *iface);

/* meshrx-callback handling */
int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio);
int dessert_meshrxcb_del(dessert_meshrxcb_t* c);

/* mesh interface handling */
int dessert_meshif_add(const char* dev, uint8_t flags);
int dessert_meshif_del(const char* dev);

dessert_meshif_t * dessert_meshif_get_name(const char* dev);
dessert_meshif_t * dessert_meshif_get_hwaddr(const uint8_t hwaddr[ETHER_ADDR_LEN]);
dessert_meshif_t * dessert_meshiflist_get(void);
/*\}*/
/***************************************************************************//**
 * @}
 *
 * @defgroup sys S Y S   -   I N T E R F A C E S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

/** flag for dessert_sysif_init - open tun (ip/ipv6) device */
#define DESSERT_TUN          0x00

/** flag for dessert_sysif_init - open tap (ethernet) device */
#define DESSERT_TAP          0x01

/** flag for dessert_sysif_init - set dessert_l25_defsrc to mac of tap device */
#define DESSERT_MAKE_DEFSRC  0x02

/** flag for dessert_sysif_init - get mac for tap failed - try mac in src of first packet */
#define _DESSERT_TAP_NOMAC   0x80

/******************************************************************************
 * functions
 ******************************************************************************/

int dessert_sysif_init(char* name, uint8_t flags);

int dessert_sysrxcb_add(dessert_sysrxcb_t* c, int prio);
int dessert_sysrxcb_del(dessert_sysrxcb_t* c);

int dessert_syssend_msg(dessert_msg_t *msg);
int dessert_syssend(const void *pkt, size_t len);

/***************************************************************************//**
 * @}
 *
 * @defgroup msg M E S S A G E  _  H A N D L I N G
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

/** flag for dessert_msg.flags - message len is hlen+plen
  * if not set buffer len is assumed as DESSERT_MAXFRAMELEN + DESSERT_MSGPROCLEN */
#define DESSERT_FLAG_SPARSE 0x1

/* *********************** */

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

/** flag for dessert_msg_proc.lflags - l25 dst is one of our interfaces,
 * but we received the message not via the indented interface, e.g. we
 * overheard it  */
#define DESSERT_LFLAG_DST_SELF_OVERHEARD 0x0100

/** flag for dessert_msg_proc.lflags - l2 dst is one of our interfaces,
 * but we received the message not via the indented interface, e.g. we
 * overheard it */
#define DESSERT_LFLAG_NEXTHOP_SELF_OVERHEARD 0x0200

/* *********************** */

/** length of dessert_ext header */
#define DESSERT_EXTLEN (sizeof(struct dessert_ext) - DESSERT_MAXEXTDATALEN)

/** Reserved extension type values */
enum dessert_extensions {
  DESSERT_EXT_ANY           = 0x00, ///< dessert_ext type wildcard - any extension
  DESSERT_EXT_ETH           = 0x01, ///< ethernet header
  DESSERT_EXT_TRACE_REQ     = 0x02, ///< route trace request: A -> B
  DESSERT_EXT_TRACE_RPL     = 0x03, ///< route trace reply: B -> A
  DESSERT_EXT_PING          = 0x04, ///< ping packet
  DESSERT_EXT_PONG          = 0x05, ///< pong packet
  /* leave some space for future extensions */
  DESSERT_EXT_USER          = 0x40, ///< first dessert_ext type for usage by the user
};

/* *********************** */

/** packet tracing flag - only record hosts */
#define DESSERT_MSG_TRACE_HOST (ETHER_ADDR_LEN)

/** packet tracing flag - record interfaces */
#define DESSERT_MSG_TRACE_IFACE (3*ETHER_ADDR_LEN)

/* *********************** */

/** Returns the length of a given extension. */
static inline size_t dessert_ext_getdatalen(dessert_ext_t* ext) { return (ext->len - DESSERT_EXTLEN); }

/******************************************************************************
 * functions
 ******************************************************************************/

int dessert_msg_new(dessert_msg_t **msgout);
int dessert_msg_clone(dessert_msg_t **msgnew, const dessert_msg_t *msgold, uint8_t sparse);
int dessert_msg_check(const dessert_msg_t* msg, size_t len);
void dessert_msg_dump(const dessert_msg_t* msg, size_t len, char *buf, size_t blen);
void dessert_msg_destroy(dessert_msg_t* msg);

int dessert_msg_ethencap(const struct ether_header* eth, size_t eth_len, dessert_msg_t **msgout);
int dessert_msg_ethdecap(const dessert_msg_t* msg, struct ether_header** ethout);
struct ether_header* dessert_msg_getl25ether (const dessert_msg_t* msg);
int dessert_msg_ipencap(const uint8_t* ip, size_t len, dessert_msg_t** msgout);
int dessert_msg_ipdecap(const dessert_msg_t* msg, uint8_t** ip);

int dessert_msg_proc_clone(dessert_msg_proc_t **procnew, const dessert_msg_proc_t *procold);
void dessert_msg_proc_dump(const dessert_msg_t* msg, size_t len, const dessert_msg_proc_t *proc, char *buf, size_t blen);
void dessert_msg_proc_destroy(dessert_msg_proc_t* proc);

int dessert_msg_addpayload(dessert_msg_t* msg, void** payload, int len);
int dessert_msg_getpayload(dessert_msg_t *msg, void **payload);
int dessert_msg_addext(dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, size_t len);
int dessert_msg_delext(dessert_msg_t *msg, dessert_ext_t *ext);
int dessert_msg_resizeext(dessert_msg_t *msg, dessert_ext_t *ext, size_t new_len);
int dessert_msg_getext(const dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, int index);
int dessert_msg_get_ext_count(const dessert_msg_t* msg, uint8_t type);

int dessert_msg_dump_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_check_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_trace_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_ifaceflags_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *riface, dessert_frameid_t id);

/***************************************************************************//**
 * @}
 *
 * @defgroup periodic P E R I O D I C  _  T A S K S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

dessert_periodic_t *dessert_periodic_add(dessert_periodiccallback_t* c, void *data, const struct timeval *scheduled, const struct timeval *interval);
dessert_periodic_t *dessert_periodic_add_delayed(dessert_periodiccallback_t* c, void *data, int delay);
int dessert_periodic_del(dessert_periodic_t *p);

/***************************************************************************//**
 * @}
 *
 * @defgroup agentx NET  -  S N M P   //   A G E N T _ X
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/
/** Flag indicating the dessert_agentx_appstats_t is of type bool. */
#define DESSERT_APPSTATS_VALUETYPE_BOOL         0

/** Flag indicating the dessert_agentx_appstats_t is of type int32. */
#define DESSERT_APPSTATS_VALUETYPE_INT32        1

/** Flag indicating the dessert_agentx_appstats_t is of type uint32. */
#define DESSERT_APPSTATS_VALUETYPE_UINT32       2

/** Flag indicating the dessert_agentx_appstats_t is of type counter64. */
#define DESSERT_APPSTATS_VALUETYPE_COUNTER64    3

/** Flag indicating the dessert_agentx_appstats_t is of type octetstring. */
#define DESSERT_APPSTATS_VALUETYPE_OCTETSTRING  4

/* *********************** */

/** Flag indicating the dessert_agentx_appstats_t does not contain information regarding a node or a link. */
#define DESSERT_APPSTATS_NODEORLINK_NONE        0

/** Flag indicating the dessert_agentx_appstats_t contains information regarding a node. */
#define DESSERT_APPSTATS_NODEORLINK_NODE        1

/** Flag indicating the dessert_agentx_appstats_t contains information regarding a link. */
#define DESSERT_APPSTATS_NODEORLINK_LINK        2

/* *********************** */

/** What is considered to be TRUE in a dessert_agentx_appstats_t. */
#define DESSERT_APPSTATS_BOOL_TRUE  1

/** What is considered to be FALSE in a dessert_agentx_appstats_t. */
#define DESSERT_APPSTATS_BOOL_FALSE 0

/* *********************** */

/** Flag indicating the dessert_agentx_appparams_t is of type bool. */
#define DESSERT_APPPARAMS_VALUETYPE_BOOL         0

/** Flag indicating the dessert_agentx_appparams_t is of type int32. */
#define DESSERT_APPPARAMS_VALUETYPE_INT32        1

/** Flag indicating the dessert_agentx_appparams_t is of type uint32. */
#define DESSERT_APPPARAMS_VALUETYPE_UINT32       2

/** Flag indicating the dessert_agentx_appparams_t is of type octetstring. */
#define DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING  3

/* *********************** */

/** What is considered to be TRUE in a dessert_agentx_appparams_t. */
#define DESSERT_APPPARAMS_BOOL_TRUE  1

/** What is considered to be FALSE in a dessert_agentx_appparams_t. */
#define DESSERT_APPPARAMS_BOOL_FALSE 0

/* *********************** */

/** Flag indicating if a appstats callback entry is of type bulk. */
#define DESSERT_APPSTATS_CB_BULK   1
/** Flag indicating if a appstats callback entry is of type nobulk. */
#define DESSERT_APPSTATS_CB_NOBULK 2

/******************************************************************************
 * typedefs
 ******************************************************************************/

/** An abstract data type representing some statistical datum.*/
typedef struct dessert_agentx_appstats {

	/** A prev pointer. @internal */
	struct dessert_agentx_appstats *prev;
	/** A next pointer. @internal */
	struct dessert_agentx_appstats *next;

	/** The name of the datum. */
	char name[256];
	/** A description of the datum*/
	char desc[256];

	/** The type of the datum.
	 *
	 * @see For valid values please refer to: \n DESSERT_APPSTATS_VALUETYPE_BOOL
	 * @see DESSERT_APPSTATS_VALUETYPE_INT32
	 * @see DESSERT_APPSTATS_VALUETYPE_UINT32
	 * @see DESSERT_APPSTATS_VALUETYPE_COUNTER64
	 * @see DESSERT_APPSTATS_VALUETYPE_OCTETSTRING
	 */
	int value_type;
	/** Indicates if this datum contains information about a node or a link
	 *
	 * @see For valid values please refer to: \n  DESSERT_APPSTATS_NODEORLINK_NONE
	 * @see DESSERT_APPSTATS_NODEORLINK_NODE
	 * @see DESSERT_APPSTATS_NODEORLINK_LINK
	 */
	int node_or_link;

	/** Field representing a mac address if this datum contains information about a node or a link. */
	uint8_t macaddress1 [ETHER_ADDR_LEN];
	/** Field representing a mac address if this datum contains information about a link. */
	uint8_t macaddress2 [ETHER_ADDR_LEN];

	union {
		/** A boolean.
		 *
		 * @see For valid values please refer to: \n DESSERT_APPSTATS_BOOL_TRUE
		 * @see DESSERT_APPSTATS_BOOL_FALSE
		 */
		uint8_t  bool;
		/** A 32bit signed integer. */
		int32_t  int32;
		/** A 32bit unsigned integer. */
		uint32_t uint32;
		/** A 64bit unsigned integer with counter semantics */
		uint64_t counter64;

		struct {
			/** The length of the octetstring field. */
			uint8_t octetstring_len;
			/** Character pointer to some raw bytes. */
			char *octetstring;
		};
	};

} dessert_agentx_appstats_t;

/** An abstract data type representing some parameter.*/
typedef struct dessert_agentx_appparams {

	/** Internal. @internal */
	struct dessert_agentx_appparams *prev;
	/** Internal. @internal */
	struct dessert_agentx_appparams *next;

	/** Internal. @internal Internal. */
	uint8_t index;

	/** The name of the datum. */
	char name[256];
	/** A description of the datum*/
	char desc[256];

	/** The type of the parameter.
	 *
	 * @see For valid values please refer to: \n DESSERT_APPPARAMS_VALUETYPE_BOOL
	 * @see DESSERT_APPPARAMS_VALUETYPE_INT32
	 * @see DESSERT_APPPARAMS_VALUETYPE_UINT32
	 * @see DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING
	 */
	int value_type;

	union {
		/** A boolean.
		 *
		 * @see For valid values please refer to: \n DESSERT_APPPARAMS_BOOL_TRUE
		 * @see DESSERT_APPPARAMS_BOOL_FALSE
		 */
		uint8_t  bool;
		/** A 32bit signed integer. */
		int32_t  int32;
		/** A 32bit unsigned integer. */
		uint32_t uint32;

		struct {
			/** The length of the octetstring field. */
			uint16_t octetstring_len;
			/** Character pointer to some raw bytes. */
			char *octetstring;
		};
	};

} dessert_agentx_appparams_t;

/** Callback type to call if the AppstatsTable is asked for by some snmp client.
 *
 * @param *appstats dessert_agentx_appstats_t the statistical datum to be filled out
 *
 *
 * @retval DESSERT_OK on success
 * @retval DESSERT_ERR to remove the corresponding callback entry
 *
 */
typedef int dessert_agentx_appstatscb_get_t(struct dessert_agentx_appstats *appstats);

/** Callback type to call if the AppparamsTable is asked for by some snmp client.
 *
 * @param *appstats dessert_agentx_appparams_t the parameter to be filled out
 *
 *
 * @retval DESSERT_OK on success
 * @retval DESSERT_ERR to remove the corresponding callback entry
 *
 */
typedef int dessert_agentx_appparamscb_get_t(struct dessert_agentx_appparams *appparams);

/** Callback type to call if the specific row represented by this callback is
 *  going to be set by some snmp client.
 *
 * @param *appstats dessert_agentx_appparams_t the new value
 *
 *
 * @retval DESSERT_OK on success
 * @retval DESSERT_ERR otherwise
 *
 */
typedef int dessert_agentx_appparamscb_set_t(struct dessert_agentx_appparams *appparams);

/** A callback entry representing a statistical datum. */
typedef struct dessert_agentx_appstats_cb_entry {

	/** Interal. @internal */
	struct dessert_agentx_appstats_cb_entry *prev;
	/** Interal. @internal */
	struct dessert_agentx_appstats_cb_entry *next;

	/** Flag indicating whether this entry represents a bulk entry.*/
	uint8_t isbulk_flag;

	/** The getter callback. */
	dessert_agentx_appstatscb_get_t *c;

} dessert_agentx_appstats_cb_entry_t;

/** A callback entry representing a parameter. */
typedef struct dessert_agentx_appparams_cb_entry {

	/** Internal. @internal */
	struct dessert_agentx_appparams_cb_entry *prev;
	/** Internal. @internal*/
	struct dessert_agentx_appparams_cb_entry *next;

	/** Internal. @internal */
	uint8_t index;

	/** The getter callback. */
	dessert_agentx_appparamscb_get_t *get;
	/** The setter callback. */
	dessert_agentx_appparamscb_set_t *set;

} dessert_agentx_appparams_cb_entry_t;


/******************************************************************************
 * globals
 ******************************************************************************/


/******************************************************************************
 * functions
 ******************************************************************************/
dessert_agentx_appstats_t *dessert_agentx_appstats_new(void);
void dessert_agentx_appstats_destroy(dessert_agentx_appstats_t *appstat);

dessert_agentx_appstats_cb_entry_t *dessert_agentx_appstats_add(dessert_agentx_appstatscb_get_t *c);
dessert_agentx_appstats_cb_entry_t *dessert_agentx_appstats_add_bulk(dessert_agentx_appstatscb_get_t *c);
int dessert_agentx_appstats_del(dessert_agentx_appstats_cb_entry_t *e);

dessert_agentx_appparams_t *dessert_agentx_appparam_new(void);
void dessert_agentx_appparam_destroy(dessert_agentx_appparams_t *appparam);

dessert_agentx_appparams_cb_entry_t *dessert_agentx_appparams_add(dessert_agentx_appparamscb_get_t *get, dessert_agentx_appparamscb_set_t *set);
int dessert_agentx_appparams_del(dessert_agentx_appparams_cb_entry_t *e);

/**************************************************************************//**
 * @}
 *
 * @defgroup macros U S E F U L L  _  MA C R O S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/

/** A convenience macro to safely iterate the list of mesh interfaces.
 *
 * @param __interface pointer to a temporal dessert_meshif_t
 *
 * @warning You must pair it with an ending MESHIFLIST_ITERATOR_STOP() macro!
 * Please find an usage example in the Examples paragraph below.
 *
 * @par Examples:
 *
 * @li The do_something() function will be called for every mesh interface in the list.
 * @code
 *  dessert_meshif_t *iface;
 *
 *  MESHIFLIST_ITERATOR_START(iface)
 *     do_something(iface); // do something to every iface
 *  MESHIFLIST_ITERATOR_STOP;
 * @endcode
 */
#define MESHIFLIST_ITERATOR_START(__interface) \
pthread_rwlock_rdlock(&dessert_cfglock); \
DL_FOREACH(dessert_meshiflist_get(), __interface) {

/** A convenience macro to safely iterate the list of mesh interfaces.
 *
 * @see MESHIFLIST_ITERATOR_START()
 */
#define MESHIFLIST_ITERATOR_STOP } pthread_rwlock_unlock(&dessert_cfglock)

/** A convenience macro to safely add @a __sec seconds and @a __usec microseconds
 *  to the @c struct @c timeval @a __tv in an <em>invariant respecting</em> manner.
 *
 * @param __tv   the @c struct @c timeval to add to
 * @param __sec  the number of seconds to add up to @a __tv->tv_sec
 * @param __usec the number of microseconds to add up to @a __tv.->tv_usec
 *
 * %DESCRIPTION: \n
 * The <a href="http://www.gnu.org/s/libc/manual/html_node/Elapsed-Time.html#Elapsed-Time">GNU C Library Documentation</a>
 * states about the @c tv_usec member of the @c struct @c timeval: <em>This is the
 * rest of the elapsed time (a fraction of a second), represented as the number
 * of microseconds. It is always less than one @a million.</em>
 *
 */
#define TIMEVAL_ADD(__tv, __sec, __usec)       \
    do {                                       \
        (__tv)->tv_sec  += __sec;              \
        (__tv)->tv_usec += __usec;             \
        if((__tv)->tv_usec >= 1000000) {       \
            ++(__tv)->tv_sec;                  \
            (__tv)->tv_usec -= 1000000;        \
        }                                      \
    } while(0)

#define likely(x)       (__builtin_expect((x),1))
#define unlikely(x)     (__builtin_expect((x),0))

#define __dessert_assert(func, file, line, e) \
    ((void)_dessert_log(LOG_EMERG, func, file, line, "assertion `%s' failed!\n", e), abort)

/** Assertion Macro
 * 
 * The assertion macro enables to crash the daemon when a particular
 * condition does not apply. In contrast to the standard C library assert,
 * a message will be written using the logging feature of DES-SERT
 */
#ifdef NDEBUG
#define assert(e)       ((void)0)
#else
#define assert(e) \
    (__builtin_expect(!(e), 0) ? __dessert_assert(__FUNCTION__, __FILE__, __LINE__, #e) : (void)0)
#endif

/** @} */

/******************************************************************************
 *
 * ! ! ! ! MOVED TO CALLBACKS DIR ! ! !
 *
 ******************************************************************************/
/**************************************************************************//**
 * @}
 *
 * @defgroup callbacks U S E F U L L  _  C A L L B A C K S
 *
 * @brief EXTERNAL / PUBLIC
 *
 * @{
 ******************************************************************************/
 
int dessert_cli_cmd_addsysif(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_cli_cmd_addmeshif(struct cli_def *cli, char *command, char *argv[], int argc);

int dessert_cli_cmd_ping(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_rx_ping(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_rx_pong(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

int dessert_cli_cmd_traceroute(struct cli_def *cli, char *command, char *argv[], int argc);
int dessert_rx_trace(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_msg_trace_initiate(dessert_msg_t* msg, uint8_t type, int mode);
int dessert_msg_trace_dump(const dessert_msg_t* msg, uint8_t type, char* buf, int blen);

int dessert_rx_ipttl(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);

int dessert_tx_drop_ipv6(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_sysif_t *iface, dessert_frameid_t id);
int dessert_rx_drop_tap(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id);
int dessert_rx_drop_tun(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id); 

#endif /* DESSERT_H*/
