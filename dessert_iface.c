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
#ifdef TARGET_FREEBSD
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif


/* data storage */
dessert_meshif_t *_dessert_meshiflist = NULL;
dessert_meshrxcbe_t *_dessert_meshrxcblist;
int _dessert_meshrxcblistver = 0;



/* local functions */
void _dessert_packet_process (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *_dessert_meshif_add_thread(void* arg);


/** internal function to send packet via a single interface */
inline int _dessert_meshsend_if2(dessert_msg_t* msg, dessert_meshif_t *iface) 
{
    int res;
    uint8_t oldflags;
    size_t msglen = ntohs(msg->hlen)+ntohs(msg->plen);
    
    /* check for null meshInterface */
    if(iface == NULL) {
        dessert_err("NULL-pointer given as interface - programming error!");
        return EINVAL;
    }
    
    /* send packet - temporally setting DESSERT_FLAG_SPARSE */
    oldflags = msg->flags;
    msg->flags &= ~DESSERT_FLAG_SPARSE;
    res = pcap_inject(iface->pcap, (u_char *) msg, msglen);
    msg->flags = oldflags;
    
    if(res != msglen) {
        if(res == -1) {
            dessert_warn("couldn't send message: %s\n", pcap_geterr(iface->pcap));
        } else {
            dessert_warn("couldn't send message: sent only %d of %d bytes\n",
                res, msglen);
        }
        return(EIO);        
    }
    
    pthread_mutex_lock(&(iface->cnt_mutex));
    iface->opkts++;
    iface->obytes+=res;
    pthread_mutex_unlock(&(iface->cnt_mutex));
    
    return(DESSERT_OK);
    
}


/**sends a dessert_msg via the specified interface or all interfaces
 * the original message buffer will not be altered, and the ethernet
 * src address will be set correctly
 * @arg *msg message to send
 * @arg *iface interface to send from - use NULL for all interfaces
 * @return DESSERT_OK on success
 * @return EINVAL     if message is broken
 * @return EIO        if message was not sent successfully
 * %DESCRIPTION:
**/
int dessert_meshsend(const dessert_msg_t* msgin, const dessert_meshif_t *iface)
{
    dessert_msg_t* msg;
    int res;
    
    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen+msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }
    
    
    /* clone message */
    dessert_msg_clone(&msg, msgin, 1);
    res = dessert_meshsend_fast(msg, iface);
    dessert_msg_destroy(msg);
    
    return res;

}

/**sends a dessert_msg via all interfaces, except via the specified interface
 * the original message buffer will not be altered, and the ethernet
 * src address will be set correctly
 * @arg *msg message to send
 * @arg *iface interface NOT to send from - use NULL for all interfaces
 * @return DESSERT_OK on success
 * @return EINVAL     if message is broken
 * @return EIO        if message was not sent successfully
 * %DESCRIPTION:
**/
int dessert_meshsend_allbutone(const dessert_msg_t* msgin, const dessert_meshif_t *iface)
{
    dessert_msg_t* msg;
    int res;

    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen+msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }


    /* clone message */
    dessert_msg_clone(&msg, msgin, 1);
    res = dessert_meshsend_fast_allbutone(msg, iface);
    dessert_msg_destroy(msg);

    return res;

}

/**sends a dessert_meshsend_fast via the specified interface or all interfaces
 * this method is faster than dessert_meshsend, but does not check the message
 * and may alter the message buffer.
 * @arg *msg message to send
 * @arg *iface interface to send from
 * @return DESSERT_OK   on success
 * @return EINVAL       if message is broken
 * @return EIO          if message was not sent successfully
 * %DESCRIPTION:
**/
int dessert_meshsend_fast(dessert_msg_t* msg, const dessert_meshif_t *iface) 
{
    int res;
    
    /* we have no iface - send on all! */
    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        for(iface = _dessert_meshiflist; iface != NULL; iface = iface->next) {
            /* set shost */
            memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
            /* send */
            res = _dessert_meshsend_if2(msg, iface);
            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    } else {
        /* set shost */
        memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
        /* send */
        res = _dessert_meshsend_if2(msg, iface);
    }
    
    return(res);
    
}

/**sends a dessert_meshsend_fast via all interface, except  the specified interface
 * this method is faster than dessert_meshsend, but does not check the message
 * and may alter the message buffer.
 * @arg *msg message to send
 * @arg *iface interface to NOT send from - use NULL for all interfaces
 * @return DESSERT_OK   on success
 * @return EINVAL       if message is broken
 * @return EIO          if message was not sent successfully
 * %DESCRIPTION:
**/
int dessert_meshsend_fast_allbutone(dessert_msg_t* msg, const dessert_meshif_t *iface)
{
	dessert_meshif_t *cur_iface;
    int res;

    /* we have no iface - send on all! */
    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        for(iface = _dessert_meshiflist; iface != NULL; iface = iface->next) {
            /* set shost */
            memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
            /* send */
            res = _dessert_meshsend_if2(msg, iface);
            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    } else {
    	pthread_rwlock_rdlock(&dessert_cfglock);
		for(curr_iface = _dessert_meshiflist; curr_iface != iface; curr_iface = curr_iface->next) {
			/* set shost */
			memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
			/* send */
			res = _dessert_meshsend_if2(msg, curr_iface);
			if(res) {
				break;
			}
		}
		pthread_rwlock_unlock(&dessert_cfglock);
    }

    return(res);

}

/**sends a dessert message via the specified interface or all interfaces
 * this method is faster than dessert_meshsend, but does not check the message
 * and may alter the message buffer. In contrast to dessert_meshsend_fast it
 * does not write the ether_shost address.
 * @arg *msg message to send
 * @arg *iface interface to send from
 * @return DESSERT_OK   on success
 * @return EINVAL       if message is broken
 * @return EIO          if message was not sent successfully
 * %DESCRIPTION:
**/
int dessert_meshsend_raw(dessert_msg_t* msg, const dessert_meshif_t *iface) 
{
    int res;
    
    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        for(iface = _dessert_meshiflist; iface != NULL; iface = iface->next) {
            res = _dessert_meshsend_if2(msg, iface);
            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    } else {
        res = _dessert_meshsend_if2(msg, iface);
    }
    
    return(res);
    
}



/** removes all occurrences of the callback function from the list of callbacks
 * @arg c callback function pointer
 * @return DESSERT_OK   on success, DESSERT_ERR otherwise
**/
int dessert_meshrxcb_del(dessert_meshrxcb_t* c)
{
    int count = 0;
    dessert_meshrxcbe_t *i, *last;
    
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    if(_dessert_meshrxcblist == NULL) {
        count++;
        goto dessert_meshrxcb_del_out;
    }
    
    while(_dessert_meshrxcblist->c == c) {
        count++;
        i = _dessert_meshrxcblist;
        _dessert_meshrxcblist = _dessert_meshrxcblist->next;
        free(i);
        if (_dessert_meshrxcblist == NULL) {
            goto dessert_meshrxcb_del_out;
        }
    }
    
    for(i = _dessert_meshrxcblist; i->next != NULL ; i=i->next) {
        if(i->c == c) {
            count++;
            last->next = i->next;
            free(i);
            i = last;
        }
        last = i;
    }
    
    
dessert_meshrxcb_del_out:
    _dessert_meshrxcblistver++;
    pthread_rwlock_unlock(&dessert_cfglock);
    return((count>0)?DESSERT_OK:DESSERT_ERR);
    
}



/** adds a callback function to call if a packet is received via a dessert interface
 * @arg c    callback function
 * @arg prio priority of the function - lower first!
 * @return DESSERT_OK -- on success
 * @return -errno     -- on error
**/
int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio)
{
    dessert_meshrxcbe_t *cb, *i;
    
    cb = (struct dessert_meshrxcbe*) malloc(sizeof(struct dessert_meshrxcbe));
    if(cb == NULL)
        return(-errno);
    
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    cb->c    = c;
    cb->prio = prio;
    cb->next = NULL;
    
    if(_dessert_meshrxcblist == NULL) {
        _dessert_meshrxcblist = cb;
        _dessert_meshrxcblistver++;
        
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }
    
    if(_dessert_meshrxcblist->prio > cb->prio) {
        cb->next = _dessert_meshrxcblist;
        _dessert_meshrxcblist = cb;
        _dessert_meshrxcblistver++;
        
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }
    
    /* find right place for callback */
    for(i = _dessert_meshrxcblist; i->next != NULL && i->next->prio <= cb->prio; i=i->next);
    
    /* insert it */
    cb->next = i->next;
    i->next = cb;
    _dessert_meshrxcblistver++;
    
    pthread_rwlock_unlock(&dessert_cfglock);
    return DESSERT_OK;
}

/** run all registered callbacks - use with care - never register as callback!
  * @returns return status of the last callback called
  */
int dessert_meshrxcb_runall(dessert_msg_t* msg_in, size_t len, dessert_msg_proc_t *proc_in, const dessert_meshif_t *despif, dessert_frameid_t id) 
{
    dessert_msg_t *msg = msg_in;
    dessert_msg_proc_t *proc = proc_in;
    dessert_meshrxcbe_t *cb;
    int res = 0;
    dessert_meshrxcb_t **cbl = NULL;
    int cbllen = 0;
    int cblcur = -1;
    
    /* copy callbacks to internal list to release dessert_cfglock before invoking callbacks*/
    pthread_rwlock_rdlock(&dessert_cfglock);
    cbllen = 0;
    for(cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next)
        cbllen++;
    cbl = malloc(cbllen*sizeof(dessert_meshrxcb_t *));
    if (cbl == NULL) {
        dessert_err("failed to allocate memory for internal callback list");
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_MSG_DROP;
    }
    
    cblcur = 0;
    for(cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next)
        cbl[cblcur++] = cb->c;
    
    pthread_rwlock_unlock(&dessert_cfglock);
    
    /* call the interested */
    res = 0;
    cblcur = 0;
    while(res > DESSERT_MSG_DROP && cblcur < cbllen) {
        
        _dessert_packet_process_cbagain:
        res = cbl[cblcur](msg, len, proc, despif, id);
        
        if(res == DESSERT_MSG_NEEDNOSPARSE && msg == msg_in){
            dessert_msg_clone(&msg, msg_in, 0);
            len = DESSERT_MAXFRAMEBUFLEN;
            goto _dessert_packet_process_cbagain;
        } else if(res == DESSERT_MSG_NEEDNOSPARSE && msg != msg_in) {
            dessert_warn("bogus DESSERT_MSG_NEEDNOSPARSE returned from callback!");
        }
        
        if(res == DESSERT_MSG_NEEDMSGPROC && proc == NULL) {
            proc = malloc(DESSERT_MSGPROCLEN);
            memset(proc, 0, DESSERT_MSGPROCLEN);
            goto _dessert_packet_process_cbagain;
        } else if (res == DESSERT_MSG_NEEDMSGPROC && proc != NULL) {
            dessert_warn("bogus DESSERT_MSG_NEEDMSGPROC returned from callback!");
        }
        
        cblcur++;
    }
    
    free(cbl);
    
    if (msg != msg_in)
        dessert_msg_destroy(msg);
    
    if (proc != proc_in) 
        free(proc);
    
    return(res);
}


/** callback doing the main work for packets received through a dessert interface
 * @param arg    - despif-pointer carried by libpcap in something else
 * @param header - pointer to the header by libpcap
 * @param packet - pointer to the packet by libpcap
**/
void _dessert_packet_process (u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    dessert_meshif_t *despif = (dessert_meshif_t *) args;
    dessert_msg_t *msg = (dessert_msg_t *) packet;
    size_t len = header->caplen;
    dessert_frameid_t id;
    dessert_msg_proc_t proc;
    
    /* is it something I understand? */
    if(ntohs(msg->l2h.ether_type) != DESSERT_ETHPROTO) {
        dessert_debug("got packet with ethertype %04x - discarding", ntohs(msg->l2h.ether_type));
        return;
    }
    
    /* check message */
    if ( header->caplen < header->len) {
        dessert_warn("packet too short - check pcap_open_live() parameters");
        return;
    }
    if( header->caplen < DESSERT_MSGLEN) {
        dessert_notice("packet too short - shorter than DESSERT_MSGLEN");
        return;
    }
        
    /* generate frame id */
    id = dessert_newframeid();
    memset(&proc, 0, DESSERT_MSGPROCLEN);
    
    /* count packet */
    pthread_mutex_lock(&(despif->cnt_mutex));
    despif->ipkts++;
    despif->ibytes+=header->caplen;
    pthread_mutex_unlock(&(despif->cnt_mutex));
    
    dessert_meshrxcb_runall(msg, len, &proc, despif, id);

}


/** callback to set the local processing flags in dessert_msg_proc_t on an arriving dessert_msg_t
 * @arg *msg dessert_msg_t frame received
 * @arg len length of ethernet frame received
 * @arg *iface interface received packet on
 * ®return DESSERT_MSG_KEEP or DESSERT_MSG_NEEDMSGPROC
**/
int dessert_msg_ifaceflags_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *riface, dessert_frameid_t id)
{

    dessert_meshif_t *iface;
    struct ether_header *l25h;
    
    /* check if we have an processing header */
    if(proc == NULL)
        return DESSERT_MSG_NEEDMSGPROC;

    /* get l2.5 header if possible */
    l25h = dessert_msg_getl25ether(msg);

    /* clear flags */
    proc->lflags &= ~( DESSERT_LFLAG_DST_SELF          | DESSERT_LFLAG_SRC_SELF
                     | DESSERT_LFLAG_NEXTHOP_SELF      | DESSERT_LFLAG_PREVHOP_SELF
                     | DESSERT_LFLAG_NEXTHOP_BROADCAST );
    
    /* checks against defaults */
    if(l25h != NULL && memcmp(l25h->ether_dhost, ether_broadcast, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_DST_BROADCAST;
    }
    else if(l25h != NULL && l25h->ether_dhost[0]&0x01) { /* broadcast also has this bit set */
        proc->lflags |= DESSERT_LFLAG_DST_MULTICAST;
    }
    
    if(l25h != NULL && memcmp(l25h->ether_dhost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_DST_SELF;
    }
    if(l25h != NULL && memcmp(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_SRC_SELF;
    }
    if(memcmp(msg->l2h.ether_dhost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_NEXTHOP_SELF;
    }
    if(memcmp(msg->l2h.ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_PREVHOP_SELF;
    }
    if(memcmp(msg->l2h.ether_dhost, ether_broadcast, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_LFLAG_NEXTHOP_BROADCAST;
    }

    /* checks against interfaces in list */
    pthread_rwlock_rdlock(&dessert_cfglock);
    for(iface = _dessert_meshiflist; iface != NULL; iface = iface->next) {
        if(l25h != NULL && memcmp(l25h->ether_dhost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_LFLAG_DST_SELF;
        }
        if(l25h != NULL && memcmp(l25h->ether_shost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_LFLAG_SRC_SELF;
        }
        if(memcmp(msg->l2h.ether_dhost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_LFLAG_NEXTHOP_SELF;
        }
        if(memcmp(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_LFLAG_PREVHOP_SELF;
        }
    }
    pthread_rwlock_unlock(&dessert_cfglock);
    
    return DESSERT_MSG_KEEP;
    
}

/** returns the head of the list of mesh interfaces (_desert_meshiflist)
 * @return pointer if list is not empty, NULL otherwise
 */
dessert_meshif_t* dessert_meshiflist_get() {
	return _dessert_meshiflist;
}


/** looks for interface with name dev in _dessert_meshiflist and returns pointer
 * @arg *dev interface name
 * @return pointer when interface found, NULL otherwise
**/
dessert_meshif_t* dessert_meshif_get(const char* dev)
{
    dessert_meshif_t *despif;
    
    /* search dev name in iflist */
    despif  = _dessert_meshiflist;
    pthread_rwlock_rdlock(&dessert_cfglock);
    while (despif != NULL && strncmp(despif->if_name, dev, IF_NAMESIZE) != 0) {
        despif = despif->next;
    }
    pthread_rwlock_unlock(&dessert_cfglock);
    
    
    return(despif);
}



/** removes the corresponding desp2_if struct from _dessert_meshiflist and does some cleanup.
 * @arg dev interface name to remove from list
 * %RETURNS:
 * @return DESSERT_OK   on success 
 * @return -errno       on error
**/
int dessert_meshif_del(const char* dev)
{
    dessert_meshif_t *despif;
    dessert_meshif_t *despif_prev;
    
    /* lock the list */
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    /* search dev name in iflist */
    despif  = _dessert_meshiflist;
    while (despif != NULL && strncmp(despif->if_name, dev, IF_NAMESIZE) != 0) {
        despif_prev = despif;
        despif = despif->next;
    }
    
    if (despif == NULL) {
        pthread_rwlock_unlock(&dessert_cfglock);
        return(ENODEV);
    }
    
    /* remove it from list */
    if (despif == _dessert_meshiflist) {
        _dessert_meshiflist = despif->next;
    } else {
        despif_prev->next = despif->next;
    }
    
    pthread_rwlock_unlock(&dessert_cfglock);
    
    /* tell pcap not to further process packets */
    pcap_breakloop(despif->pcap);
    
    
    /* the remaining cleanup is done in the interface thread *
     * using _dessert_meshif_cleanup                              */
    
    return DESSERT_OK;
    
}

/** internal routine called before interface thread finishes */
void _dessert_meshif_cleanup (dessert_meshif_t *despif) 
{
    pcap_close(despif->pcap);
    free(despif);
}



/** Initializes the des-sert Interface, starts packet processor thread and registers all
 * @arg dev interface name
 * @return DESSERT_OK   on success
 * @return DESSERT_ERR  on error
**/
int dessert_meshif_add(const char* dev, uint8_t flags) 
{
    dessert_meshif_t *despif;
    
    uint8_t promisc = (flags & DESSERT_IF_NOPROMISC)?0:1;
    struct bpf_program fp; /* filter program for libpcap */
    char fe[64];           /* filter expression for libpcap */
    
    snprintf(fe, 64, "ether proto 0x%04x", DESSERT_ETHPROTO);
    
    
    /* init new interface entry */
    despif = (dessert_meshif_t*) malloc(sizeof(dessert_meshif_t));
    if(despif == NULL)
        return(-errno);
    memset((void *)despif, 0, sizeof(dessert_meshif_t));
    strncpy(despif->if_name, dev, IF_NAMESIZE);
    despif->if_name[IF_NAMESIZE-1] = '\0';
    despif->if_index = if_nametoindex(dev);
    pthread_mutex_init(&(despif->cnt_mutex), NULL);
    
    /* check if interface exists */
    if(!despif->if_index) {
        dessert_err("interface %s - no such interface", despif->if_name);
        goto dessert_meshif_add_err;
    }
    
    
    /* initialize libpcap */
    despif->pcap = pcap_open_live(despif->if_name, DESSERT_MAXFRAMELEN, promisc, 10, despif->pcap_err);
    if (despif->pcap == NULL) {
        dessert_err("pcap_open_live failed for interface %s(%d):\n%s",
            despif->if_name, despif->if_index, despif->pcap_err);
        goto dessert_meshif_add_err;
    }
    if(pcap_datalink(despif->pcap) != DLT_EN10MB) {
        dessert_err("interface %s(%d) is not an ethernet interface!",
            despif->if_name, despif->if_index);
        goto dessert_meshif_add_err;
    }
    
    /* pcap filter */
    if(!(flags & DESSERT_IF_NOFILTER)) {
        if (pcap_compile(despif->pcap, &fp, fe, 0, 0) == -1) {
            dessert_err("couldn't parse filter %s: %s\n", fe, pcap_geterr(despif->pcap));
            goto dessert_meshif_add_err;
        }
        if (pcap_setfilter(despif->pcap, &fp) == -1) {
            dessert_err("couldn't install filter %s: %s\n", fe, pcap_geterr(despif->pcap));
            goto dessert_meshif_add_err;
        }
    }
    
    
    /* get hardware address */
    if(_dessert_meshif_gethwaddr(despif) != 0) {
        dessert_err("failed to get hwaddr of interface %s(%d)", 
            despif->if_name, despif->if_index);
        goto dessert_meshif_add_err;
    }
    
    /* check whether we need to set defsrc (default source) */
    if (memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0) {
        memcpy(dessert_l25_defsrc, despif->hwaddr, ETHER_ADDR_LEN);
        dessert_info("set dessert_l25_defsrc to hwaddr %02x:%02x:%02x:%02x:%02x:%02x", 
            dessert_l25_defsrc[0], dessert_l25_defsrc[1],dessert_l25_defsrc[2],
            dessert_l25_defsrc[3], dessert_l25_defsrc[4], dessert_l25_defsrc[5]);
    }
    
    
    dessert_info("starting worker thread for interface %s(%d) hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
        despif->if_name, despif->if_index, 
        despif->hwaddr[0], despif->hwaddr[1], despif->hwaddr[2],
        despif->hwaddr[3], despif->hwaddr[4], despif->hwaddr[5]);
    
    
    /* start worker thread */
    if(pthread_create(&(despif->worker), NULL, _dessert_meshif_add_thread, (void *) despif)) {
        dessert_err("creating worker thread failed for interfcae %s(%d)",
            despif->if_name, despif->if_index);
        goto dessert_meshif_add_err;
    }
    
    
    /* prepend to interface list */
    pthread_rwlock_wrlock(&dessert_cfglock);
    if(_dessert_meshiflist != NULL) 
       despif->next=_dessert_meshiflist;
    _dessert_meshiflist = despif;
    pthread_rwlock_unlock(&dessert_cfglock);
    
    
    return(DESSERT_OK);
    
    
dessert_meshif_add_err:

    if(despif->pcap != NULL) {
        pcap_close(despif->pcap);
    }
    free(despif);
    return(DESSERT_ERR);
}

/** internal thread function running the capture loop */
void *_dessert_meshif_add_thread(void* arg) {

    dessert_meshif_t *despif = (dessert_meshif_t *) arg;

    pcap_loop(despif->pcap, -1, _dessert_packet_process, (u_char *) despif);
    
    _dessert_meshif_cleanup(despif);
    
    return (NULL);

}

/** get hardware address of the ethernet device behind despif
 * this more are platform depending functions!
 * @arg *despif pointer to desp2_if to query
 * @return DESSERT_OK on success
**/
int _dessert_meshif_gethwaddr(dessert_meshif_t *despif)
#ifdef TARGET_DARWIN
{
    /* the Apple way... */

    int                     mib[6];
    size_t                  len;
    uint8_t                 *buf, *next;
    struct if_msghdr        *ifm;
    struct sockaddr_dl      *sdl;
    int ret = DESSERT_ERR;
    
    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;
    
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
            dessert_err("Acquiring hwaddr failed: sysctl 1 error");
            return(DESSERT_ERR);
    }
    
    if ((buf = malloc(len)) == NULL) {
            dessert_err("acquiring hwaddr failed: malloc error");
            return(DESSERT_ERR);
    }
    
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
            dessert_err("acquiring hwaddr failed: sysctl 2 error");
            return(DESSERT_ERR);
    }
    
    for (next = buf; next < buf+len; next += ifm->ifm_msglen) {
        ifm = (struct if_msghdr *)next;
        if (ifm->ifm_type == RTM_IFINFO) {
            sdl = (struct sockaddr_dl *)(ifm + 1);
            if (strncmp(&sdl->sdl_data[0], despif->if_name, sdl->sdl_len) == 0) {
                memcpy(despif->hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
                ret = DESSERT_OK;
                break;
            }
        }
    }
    
    free(buf);
    return ret;
}
#elif TARGET_FREEBSD
{
    struct ifaddrs   *ifaphead;
    struct ifaddrs   *ifap;
    struct sockaddr_dl *sdl = NULL;

    if (getifaddrs(&ifaphead) != 0)
    {
        dessert_err("getifaddrs() failed");
        return(DESSERT_ERR);
    }

    for (ifap = ifaphead; ifap ; ifap = ifap->ifa_next)
    {
        if ((ifap->ifa_addr->sa_family == AF_LINK))
        {
            if (strcmp(ifap->ifa_name,despif->if_name) == 0)
            {
                sdl = (struct sockaddr_dl *)ifap->ifa_addr;
                if (sdl)
                {
                    memcpy(despif->hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
                    return(DESSERT_OK);
                }
            }
        }
    }
    return(DESSERT_ERR);
}
#elif TARGET_LINUX
{
    /* the linux and solaris way */
    int sockfd;
    struct ifreq ifr;
    
    /* we need some socket to do that */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* set interface options and get hardware address */
    strncpy(ifr.ifr_name,despif->if_name,sizeof(ifr.ifr_name));
    

    #ifdef SIOCGIFHWADDR
    if ( ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0 ) {
        memcpy( despif->hwaddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN );
    /* } */
    #elif defined SIOCGENADDR
    if ( ioctl(sd, SIOCGENADDR, &ifr_work) >= 0 ) {
        memcpy( despif->hwaddr, &ifr.ifr_enaddr, ETHER_ADDR_LEN );
    /* } */    
    #else
    if(false) {
    #endif
        close(sockfd);
        return(DESSERT_OK);
    } else {
        dessert_err("acquiring hwaddr failed");
        close(sockfd);
        return(DESSERT_ERR);
    }
}
#else
int _dessert_meshif_gethwaddr(dessert_meshif_t *iface) {
    dessert_err("acquiring hwaddr failed - platform not supported");
    return(DESSERT_ERR);
}
#endif

