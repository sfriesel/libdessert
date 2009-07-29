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

#ifdef TARGET_DARWIN
#define TUNSIFHEAD  _IOW('t', 96, int)
#define TUNGIFHEAD  _IOR('t', 97, int)
#endif

#ifdef TARGET_FREEBSD
#include <net/if_tun.h>
#endif

#ifdef TARGET_LINUX
#include <linux/if_tun.h>
#endif


/* data storage */
dessert_tunif_t *_dessert_tunif = NULL;
uint8_t dessert_tunif_hwaddr[ETHER_ADDR_LEN];
dessert_tunrxcbe_t *_dessert_tunrxcblist = NULL;
int _dessert_tunrxcblistver = 0;



/* internal functions */
void *_dessert_tunif_init_thread(void* arg);
int _dessert_tunif_init_getmachack (dessert_msg_t *msg, size_t len, dessert_msg_proc_t *proc, dessert_tunif_t *tunif, dessert_frameid_t id);



/** Initializes the tun/tap Interface dev for des-sert.
 * @arg *device interface name
 * @arg flags  @see DESSERT_TUN @see DESSERT_TAP @see DESSERT_MAKE_DEFSRC 
 * @return 0       -- on success
 * @return EINVAL  -- if message is broken
 * @return EFAULT  -- if interface not specified and not guessed
**/
int dessert_tunif_init(char* device, uint8_t flags)
{

    char *buf;
    
#ifdef TARGET_LINUX
    struct ifreq ifr;
#endif
    
    /* initialize _dessert_tunif */
    _dessert_tunif = malloc(sizeof(dessert_tunif_t));
    if(_dessert_tunif == NULL)
        return(-errno);
    memset((void *)_dessert_tunif, 0, sizeof(dessert_tunif_t));
    _dessert_tunif->flags = flags;
    strncpy(_dessert_tunif->if_name, device, IF_NAMESIZE);
    _dessert_tunif->if_name[IF_NAMESIZE-1] = '\0';
    pthread_mutex_init(&(_dessert_tunif->cnt_mutex), NULL);
    
    
#ifdef TARGET_BSD
    
    /* open device */
    buf = malloc(IF_NAMESIZE+6);
    snprintf(buf, IF_NAMESIZE+6, "/dev/%s", device);
    _dessert_tunif->fd = open(buf, O_RDWR);
    if(_dessert_tunif->fd < 0) {
        dessert_err("could not open interface %s using %s: %s", device, buf, strerror(errno));
        free(buf);
        return (-errno);
    }
    free(buf);
    
    
    /* set header mode on for mode tun */
    if(flags & DESSERT_TUN) {
        const int one = 1;
        if(ioctl(_dessert_tunif->fd, TUNSIFHEAD, &one, sizeof one) == -1) {
            dessert_err("setting TUNSIFHEAD failed: %s",strerror(errno));
            goto dessert_tunif_init_err;
            return (-errno);
        }
    }

#elif TARGET_LINUX

    /* open device */
    buf = "/dev/net/tun";
    _dessert_tunif->fd = open(buf, O_RDWR);
    memset(&ifr, 0, sizeof(ifr));
    if(flags&DESSERT_TUN) {
        ifr.ifr_flags = IFF_TUN ; /* we want the service flag - no IFF_NO_PI */
    } else {
        ifr.ifr_flags = IFF_TAP|IFF_NO_PI ; /* we want the service flag and IFF_NO_PI */
    } 
    strcpy(ifr.ifr_name, _dessert_tunif->if_name);
    if (ioctl(_dessert_tunif->fd, TUNSETIFF, (void *) &ifr) < 0) {
            dessert_err("ioctl(TUNSETIFF) failed: %s", strerror(errno));
            goto dessert_tunif_init_err;
            return (-errno);
    }
    strcpy(_dessert_tunif->if_name, ifr.ifr_name);

#else

    goto not_implemented;

#endif
        
    /* check interface - abusing dessert_meshif methods */
    _dessert_tunif->if_index = if_nametoindex(device);
    if(!_dessert_tunif->if_index) {
        dessert_err("interface %s - no such interface", _dessert_tunif->if_name);
        goto dessert_tunif_init_err;
    }
    
    /* do ifconfig to set the interface up - strange things happen otherwise */
    buf = malloc(IF_NAMESIZE+16);
    snprintf(buf, IF_NAMESIZE+15, "ifconfig %s up", _dessert_tunif->if_name);
    system(buf);
    free(buf);
    
    /* get hardware address in tap mode if possible */
    if(flags&DESSERT_TAP) {
        if(_dessert_meshif_gethwaddr((dessert_meshif_t *) _dessert_tunif) != 0) {
            dessert_err("failed to get hwaddr of interface %s(%d) - hope src of first packet received from is it",
                _dessert_tunif->if_name, _dessert_tunif->if_index, _dessert_tunif);
            _dessert_tunif->flags |= _DESSERT_TAP_NOMAC;
            dessert_tunrxcb_add(_dessert_tunif_init_getmachack, 0);
        } else {
            /* check whether we need to set defsrc */
            if ((flags & DESSERT_MAKE_DEFSRC) || 
                memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0)
            {
                memcpy(dessert_l25_defsrc, _dessert_tunif->hwaddr, ETHER_ADDR_LEN);
                dessert_info("set dessert_l25_defsrc to hwaddr %02x:%02x:%02x:%02x:%02x:%02x", 
                    dessert_l25_defsrc[0], dessert_l25_defsrc[1],dessert_l25_defsrc[2],
                    dessert_l25_defsrc[3], dessert_l25_defsrc[4], dessert_l25_defsrc[5]);
            }
        }
    }
    
    
    /* info message */
    if(flags&DESSERT_TAP) {
        dessert_info("starting worker thread for tap interface %s(%d) hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
            _dessert_tunif->if_name, _dessert_tunif->if_index, 
            _dessert_tunif->hwaddr[0], _dessert_tunif->hwaddr[1], _dessert_tunif->hwaddr[2],
            _dessert_tunif->hwaddr[3], _dessert_tunif->hwaddr[4], _dessert_tunif->hwaddr[5]);
    } else {
        dessert_info("starting worker thread for tap interface %s(%d) fd %d",
            _dessert_tunif->if_name, _dessert_tunif->if_index, _dessert_tunif->fd);
    }
        
    
    /* start worker thread */
    if(pthread_create(&(_dessert_tunif->worker), NULL, _dessert_tunif_init_thread, (void *) _dessert_tunif)) {
        dessert_err("creating worker thread failed for interface %s(%d)",
            _dessert_tunif->if_name, _dessert_tunif->if_index);
        goto dessert_tunif_init_err;
    }
    
    /* done */
    return(DESSERT_OK);
    
    dessert_tunif_init_err:
    close(_dessert_tunif->fd);

    return(-errno);
}

/** internal callback which gets registered if we can't find out mac address of tap interface */
int _dessert_tunif_init_getmachack (dessert_msg_t *msg, size_t len, dessert_msg_proc_t *proc, dessert_tunif_t *tunif, dessert_frameid_t id) {

	struct ether_header *eth;
	dessert_msg_ethdecap(msg, &eth);

    /* hack to get the hardware address */
    if(tunif->flags & _DESSERT_TAP_NOMAC) {
        /* copy from first packet received */
        memcpy(tunif->hwaddr, eth->ether_shost, ETHER_ADDR_LEN);
        dessert_info("guessed hwaddr for %s: %02x:%02x:%02x:%02x:%02x:%02x",  tunif->if_name,
                tunif->hwaddr[0], tunif->hwaddr[1], tunif->hwaddr[2],
                tunif->hwaddr[3], tunif->hwaddr[4], tunif->hwaddr[5]);
        /* check whether we need to set defsrc */
        if ((tunif->flags & DESSERT_MAKE_DEFSRC) || 
            memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0)
        {
            memcpy(dessert_l25_defsrc, tunif->hwaddr, ETHER_ADDR_LEN);
            dessert_info("set dessert_l25_defsrc to hwaddr %02x:%02x:%02x:%02x:%02x:%02x", 
                dessert_l25_defsrc[0], dessert_l25_defsrc[1],dessert_l25_defsrc[2],
                dessert_l25_defsrc[3], dessert_l25_defsrc[4], dessert_l25_defsrc[5]);
        }
        tunif->flags &= ~_DESSERT_TAP_NOMAC;
    }
    
    /* unregister me */
    dessert_tunrxcb_del(_dessert_tunif_init_getmachack);
    
    return DESSERT_MSG_KEEP;
}

/** internal packet processing thread body */
void *_dessert_tunif_init_thread(void* arg) {

    dessert_tunif_t *tunif = (dessert_tunif_t *) arg;
    size_t len;
    size_t buflen = ETHER_MAX_LEN;
    char   buf [buflen];
    dessert_msg_proc_t proc;
    dessert_frameid_t id;
    dessert_tunrxcbe_t *cb;
    int res;
    int ex = 0;
    dessert_tunrxcb_t **cbl = NULL;
    int cbllen = 0;
    int cblcur = -1;
    int cblver = -1;
    
    
    while(!ex) {
        
        memset(buf, 0, buflen);
                
        if(tunif->flags & DESSERT_TUN) {
            len = read((tunif->fd), buf+(ETHER_ADDR_LEN*2), buflen-(ETHER_ADDR_LEN*2));
        } else {
            len = read((tunif->fd), buf, buflen);
        }
        
        if(len == -1) {
            dessert_debug("got %s while reading on %s (fd %d) - is the tun interface up?", strerror(errno), tunif->if_name, tunif->fd);
            sleep(1);
            continue;
        }
        if(tunif->flags & DESSERT_TUN) {
            len+=(ETHER_ADDR_LEN*2);
        }
        
        
        /* copy callbacks to internal list to release dessert_cfglock before invoking callbacks*/
        pthread_rwlock_rdlock(&dessert_cfglock);
        if (cblver < _dessert_tunrxcblistver) {
            /* callback list changed - rebuild it */
            cbllen = 0;
            for(cb = _dessert_tunrxcblist; cb != NULL; cb = cb->next)
                cbllen++;
            cbl = realloc(cbl, cbllen*sizeof(dessert_tunrxcb_t *));
            if (cbl == NULL) {
                dessert_err("failed to allocate memory for internal callback list");
                pthread_rwlock_unlock(&dessert_cfglock);
                return(NULL);
            }
            
            cblcur = 0;
            for(cb = _dessert_tunrxcblist; cb != NULL; cb = cb->next)
                cbl[cblcur++] = cb->c;
            
            cblver = _dessert_tunrxcblistver;
        }
        pthread_rwlock_unlock(&dessert_cfglock);
        
        /* generate frame id */
        id = dessert_newframeid();
        
        /* count packet */
        pthread_mutex_lock(&(tunif->cnt_mutex));
        tunif->ipkts++;
        tunif->ibytes+=len;
        pthread_mutex_unlock(&(tunif->cnt_mutex));
        
        /* call the interested */
        res = 0;
        cblcur = 0;
        memset(&proc, 0, DESSERT_MSGPROCLEN);
        while(res >= 0 && cblcur < cbllen) {
        	dessert_msg_t *msg;
        	if (dessert_msg_ethencap((struct ether_header *) buf,len, &msg) <0){
        		dessert_err("failed to encapsulate ethernet frame on host-to-network-pipeline: %s", errno);
        	};
        	res = cbl[cblcur++](msg, len, &proc, tunif, id);
        }
        
    }
    dessert_info("stopped reading on %s (fd %d): %s", tunif->if_name, tunif->fd, strerror(errno));
    
    free(cbl);
    close(tunif->fd);   
    
    return (NULL);

}




/** removes all occurrences of the callback function from the list of callbacks.
 * @arg c callback function
 * @return DESSERT_OK   on success, DESSERT_ERR  on error
**/
int dessert_tunrxcb_del(dessert_tunrxcb_t* c)
{
    int count = 0;
    dessert_tunrxcbe_t *i, *last;
    
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    if(_dessert_tunrxcblist == NULL) {
        goto dessert_tunrxcb_del_out;
    }
    
    while(_dessert_tunrxcblist->c == c) {
        count++;
        i = _dessert_tunrxcblist;
        _dessert_tunrxcblist = _dessert_tunrxcblist->next;
        free(i);
        if (_dessert_tunrxcblist == NULL) {
            goto dessert_tunrxcb_del_out;
        }
    }
    
    for(i = _dessert_tunrxcblist; i->next != NULL ; i=i->next) {
        if(i->c == c) {
            count++;
            last->next = i->next;
            free(i);
            i = last;
        }
        last = i;
    }
    
    
dessert_tunrxcb_del_out:
    _dessert_tunrxcblistver++;
    pthread_rwlock_unlock(&dessert_cfglock);
    return((count>0)?DESSERT_OK:DESSERT_ERR);
    
}


/** adds a callback function to call if a packet should be injected into dessert via a tun/tap interface
 * @arg *c   callback function
 * @arg prio priority of the function - lower first!
 * @return DESSERT_OK   on success
 * @return -errno       on error
**/
int dessert_tunrxcb_add(dessert_tunrxcb_t* c, int prio)
{
    dessert_tunrxcbe_t *cb, *i;
    
    cb = (struct dessert_tunrxcbe*) malloc(sizeof(struct dessert_tunrxcbe));
    if(cb == NULL) {
        dessert_err("failed to allocate memory for registering tun callback: %s", strerror(errno));
        return(-errno);
    }
    
    if(c == NULL) {
        dessert_err("tried to add a null pointer as dessert_tunrxcb");
        return(-EINVAL);
    }
    
    pthread_rwlock_wrlock(&dessert_cfglock);
    
    cb->c    = c;
    cb->prio = prio;
    cb->next = NULL;
    
    
    if(_dessert_tunrxcblist == NULL) {
        _dessert_tunrxcblist = cb;
        _dessert_tunrxcblistver++;
        
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }
    
    if(_dessert_tunrxcblist->prio > cb->prio) {
        cb->next = _dessert_tunrxcblist;
        _dessert_tunrxcblist = cb;
        _dessert_tunrxcblistver++;
        
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }
    
    /* find right place for callback */
    for(i = _dessert_tunrxcblist; i->next != NULL && i->next->prio <= cb->prio; i=i->next);    
    
    /* insert it */
    cb->next = i->next;
    i->next = cb;
    _dessert_tunrxcblistver++;
    
    pthread_rwlock_unlock(&dessert_cfglock);
    return DESSERT_OK;
}



/** sends a packet via tun/tap interface to the kernel
 * @arg *eth message to send
 * @arg len length of message to send
 * @return DESSERT_OK   on success
 * @return -EIO         if message failed to be sent
**/
int dessert_tunsend(const struct ether_header *eth, size_t len)
{
    ssize_t res = 0;
    
    if(_dessert_tunif == NULL)
        return(EIO);
    
    
    if(_dessert_tunif->flags & DESSERT_TUN) {
        eth = (struct ether_header *) (((uint8_t *) eth) + (ETHER_ADDR_LEN*2));
        len -= (ETHER_ADDR_LEN*2);
    }
    
    
    res = write(_dessert_tunif->fd, (const void *) eth, len);
    
    if(res==len) {
        pthread_mutex_lock(&(_dessert_tunif->cnt_mutex));
        _dessert_tunif->opkts++;
        _dessert_tunif->obytes+=res;
        pthread_mutex_unlock(&(_dessert_tunif->cnt_mutex));
        return(DESSERT_OK);
    } else {
        return(EIO);
    }
}
 
