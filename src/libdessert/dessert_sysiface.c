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

#ifdef __DARWIN__
#define TUNSIFHEAD  _IOW('t', 96, int)
#define TUNGIFHEAD  _IOR('t', 97, int)
#endif

#ifdef __FreeBSD__
#include <net/if_tun.h>
#endif

#ifdef __linux__
#include <linux/if_tun.h>
#endif

uint8_t dessert_sysif_hwaddr[ETHER_ADDR_LEN]; // TODO unused! to be removed ??!?

/* global data storage // P U B L I C */
/* nothing here - yet */

/* global data storage // P R I V A T E */
dessert_sysif_t *_dessert_sysif = NULL;

/* local data storage*/
dessert_sysrxcbe_t *_dessert_sysrxcblist = NULL;
int _dessert_sysrxcblistver = 0;

/* internal functions forward declarations*/
static void *_dessert_sysif_init_thread(void* arg);
static int _dessert_sysif_init_getmachack(dessert_msg_t *msg, size_t len,
		dessert_msg_proc_t *proc, dessert_sysif_t *sysif, dessert_frameid_t id);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

/** Initializes the tun/tap Interface dev for des-sert.
 * @arg *device interface name
 * @arg flags  @see DESSERT_TUN @see DESSERT_TAP @see DESSERT_MAKE_DEFSRC 
 * @return 0       -- on success
 * @return EINVAL  -- if message is broken
 * @return EFAULT  -- if interface not specified and not guessed
 **/
int dessert_sysif_init(char* device, uint8_t flags) {

	char *buf;

#ifdef __linux__
	struct ifreq ifr;
#endif

	/* initialize _dessert_sysif */
	_dessert_sysif = malloc(sizeof(dessert_sysif_t));
	if (_dessert_sysif == NULL)
		return (-errno);
	memset((void *) _dessert_sysif, 0, sizeof(dessert_sysif_t));
	_dessert_sysif->flags = flags;
	strncpy(_dessert_sysif->if_name, device, IF_NAMESIZE);
	_dessert_sysif->if_name[IF_NAMESIZE - 1] = '\0';
	pthread_mutex_init(&(_dessert_sysif->cnt_mutex), NULL);

#ifdef __FreeBSD__

	/* open device */
	buf = malloc(IF_NAMESIZE+6);
	snprintf(buf, IF_NAMESIZE+6, "/dev/%s", device);
	_dessert_sysif->fd = open(buf, O_RDWR);
	if(_dessert_sysif->fd < 0) {
		dessert_err("could not open interface %s using %s: %s", device, buf, strerror(errno));
		free(buf);
		return (-errno);
	}
	free(buf);

	/* set header mode on for mode tun */
	if(flags & DESSERT_TUN) {
		const int one = 1;
		if(ioctl(_dessert_sysif->fd, TUNSIFHEAD, &one, sizeof one) == -1) {
			dessert_err("setting TUNSIFHEAD failed: %s",strerror(errno));
			goto dessert_sysif_init_err;
			return (-errno);
		}
	}

#elif __linux__

	/* open device */
	buf = "/dev/net/tun";
	_dessert_sysif->fd = open(buf, O_RDWR);
	memset(&ifr, 0, sizeof(ifr));
	if (flags & DESSERT_TUN) {
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* we want the service flag and IFF_NO_PI */
	} else {
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI; /* we want the service flag and IFF_NO_PI */
	}
	strcpy(ifr.ifr_name, _dessert_sysif->if_name);
	if (ioctl(_dessert_sysif->fd, TUNSETIFF, (void *) &ifr) < 0) {
		dessert_err("ioctl(TUNSETIFF) failed: %s", strerror(errno));
		goto dessert_sysif_init_err;
		return (-errno);
	}
	strcpy(_dessert_sysif->if_name, ifr.ifr_name);

#else

	goto not_implemented;

#endif

	/* check interface - abusing dessert_meshif methods */
	_dessert_sysif->if_index = if_nametoindex(device);
	if (!_dessert_sysif->if_index) {
		dessert_err("interface %s - no such interface", _dessert_sysif->if_name);
		goto dessert_sysif_init_err;
	}

	/* do ifconfig to set the interface up - strange things happen otherwise */
	buf = malloc(IF_NAMESIZE + 16);
	snprintf(buf, IF_NAMESIZE + 15, "ifconfig %s up", _dessert_sysif->if_name);
	system(buf);
	free(buf);

	/* get hardware address in tap mode if possible */
	if (flags & DESSERT_TAP) {
		if (_dessert_meshif_gethwaddr((dessert_meshif_t *) _dessert_sysif) != 0) {
			dessert_err("failed to get hwaddr of interface %s(%d) - hope src of first packet received from is it",
					_dessert_sysif->if_name, _dessert_sysif->if_index, _dessert_sysif);
			_dessert_sysif->flags |= _DESSERT_TAP_NOMAC;
			dessert_sysrxcb_add(_dessert_sysif_init_getmachack, 0);
		} else {
			/* check whether we need to set defsrc */
			if ((flags & DESSERT_MAKE_DEFSRC) || memcmp(dessert_l25_defsrc,
					ether_null, ETHER_ADDR_LEN) == 0) {
				memcpy(dessert_l25_defsrc, _dessert_sysif->hwaddr,
						ETHER_ADDR_LEN);
				dessert_info("set dessert_l25_defsrc to hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
						dessert_l25_defsrc[0], dessert_l25_defsrc[1],dessert_l25_defsrc[2],
						dessert_l25_defsrc[3], dessert_l25_defsrc[4], dessert_l25_defsrc[5]);
			}
		}
	}

	/* info message */
	if (flags & DESSERT_TAP) {
		dessert_info("starting worker thread for tap interface %s(%d) hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
				_dessert_sysif->if_name, _dessert_sysif->if_index,
				_dessert_sysif->hwaddr[0], _dessert_sysif->hwaddr[1], _dessert_sysif->hwaddr[2],
				_dessert_sysif->hwaddr[3], _dessert_sysif->hwaddr[4], _dessert_sysif->hwaddr[5]);
	} else {
		dessert_info("starting worker thread for tap interface %s(%d) fd %d",
				_dessert_sysif->if_name, _dessert_sysif->if_index, _dessert_sysif->fd);
	}

	/* start worker thread */
	if (pthread_create(&(_dessert_sysif->worker), NULL,
			_dessert_sysif_init_thread, (void *) _dessert_sysif)) {
		dessert_err("creating worker thread failed for interface %s(%d)",
				_dessert_sysif->if_name, _dessert_sysif->if_index);
		goto dessert_sysif_init_err;
	}

	/* done */
	return (DESSERT_OK);

	dessert_sysif_init_err: close(_dessert_sysif->fd);

	return (-errno);
}

/** adds a callback function to call if a packet should be injected into dessert via a tun/tap interface
 * @arg *c   callback function
 * @arg prio priority of the function - lower first!
 * @return DESSERT_OK   on success
 * @return -errno       on error
 **/
int dessert_sysrxcb_add(dessert_sysrxcb_t* c, int prio) {
	dessert_sysrxcbe_t *cb, *i;

	cb = (struct dessert_sysrxcbe*) malloc(sizeof(struct dessert_sysrxcbe));
	if (cb == NULL) {
		dessert_err("failed to allocate memory for registering sys callback: %s", strerror(errno));
		return (-errno);
	}

	if (c == NULL) {
		dessert_err("tried to add a null pointer as dessert_sysrxcb");
		return (-EINVAL);
	}

	pthread_rwlock_wrlock(&dessert_cfglock);

	cb->c = c;
	cb->prio = prio;
	cb->next = NULL;

	if (_dessert_sysrxcblist == NULL) {
		_dessert_sysrxcblist = cb;
		_dessert_sysrxcblistver++;

		pthread_rwlock_unlock(&dessert_cfglock);
		return DESSERT_OK;
	}

	if (_dessert_sysrxcblist->prio > cb->prio) {
		cb->next = _dessert_sysrxcblist;
		_dessert_sysrxcblist = cb;
		_dessert_sysrxcblistver++;

		pthread_rwlock_unlock(&dessert_cfglock);
		return DESSERT_OK;
	}

	/* find right place for callback */
	for (i = _dessert_sysrxcblist; i->next != NULL && i->next->prio <= cb->prio; i
			= i->next)
		;

	/* insert it */
	cb->next = i->next;
	i->next = cb;
	_dessert_sysrxcblistver++;

	pthread_rwlock_unlock(&dessert_cfglock);
	return DESSERT_OK;
}

/** removes all occurrences of the callback function from the list of callbacks.
 * @arg c callback function
 * @return DESSERT_OK   on success, DESSERT_ERR  on error
 **/
int dessert_sysrxcb_del(dessert_sysrxcb_t* c) {
	int count = 0;
	dessert_sysrxcbe_t *i, *last;

	pthread_rwlock_wrlock(&dessert_cfglock);

	if (_dessert_sysrxcblist == NULL) {
		goto dessert_sysrxcb_del_out;
	}

	while (_dessert_sysrxcblist->c == c) {
		count++;
		i = _dessert_sysrxcblist;
		_dessert_sysrxcblist = _dessert_sysrxcblist->next;
		free(i);
		if (_dessert_sysrxcblist == NULL) {
			goto dessert_sysrxcb_del_out;
		}
	}

	for (i = _dessert_sysrxcblist; i->next != NULL; i = i->next) {
		if (i->c == c) {
			count++;
			last->next = i->next;
			free(i);
			i = last;
		}
		last = i;
	}

	dessert_sysrxcb_del_out: _dessert_sysrxcblistver++;
	pthread_rwlock_unlock(&dessert_cfglock);
	return ((count > 0) ? DESSERT_OK : DESSERT_ERR);

}

/** sends a packet via tun/tap interface to the kernel
 * @arg *msg message to send
 * @return DESSERT_OK   on success
 * @return -EIO         if message failed to be sent
 **/
int dessert_syssend_msg(dessert_msg_t *msg) {
    void *pkt;
    size_t len;

    len = dessert_msg_ethdecap(msg, (struct ether_header**) &pkt);
    // lets see if the message contains an Ethernet frame
    if (len == -1) {
        // might only be an ip datagram due to TUN usage
        size_t len = dessert_msg_ipdecap(msg, (uint8_t**) &pkt);
        // if neither a Ethernet header or ip datagram are available, something must be wrong
        // also make sure to forward ip datagrams only to a TUN interface
        if (len == -1 || !_dessert_sysif|| !(_dessert_sysif->flags & DESSERT_TUN))
          return (-EIO);
    }

    dessert_syssend(pkt, len);
    free(pkt);

    return DESSERT_OK;  
}

/** sends a packet via tun/tap interface to the kernel
 * @arg *eth message to send
 * @arg len length of message to send
 * @return DESSERT_OK   on success
 * @return -EIO         if message failed to be sent
 **/
int dessert_syssend(const void* pkt, size_t len) {
	ssize_t res = 0;

	if (_dessert_sysif == NULL)
		return (-EIO);

	res = write(_dessert_sysif->fd, (const void *) pkt, len);

	if (res == len) {
		pthread_mutex_lock(&(_dessert_sysif->cnt_mutex));
		_dessert_sysif->opkts++;
		_dessert_sysif->obytes += res;
		pthread_mutex_unlock(&(_dessert_sysif->cnt_mutex));
		return (DESSERT_OK);
	} else {
		return (-EIO);
	}
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

/* nothing here - yet */

/******************************************************************************
 *
 * LOCAL
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

/** internal callback which gets registered if we can't find out mac address of tap interface */
static int _dessert_sysif_init_getmachack(dessert_msg_t *msg, size_t len,
		dessert_msg_proc_t *proc, dessert_sysif_t *sysif, dessert_frameid_t id) {

	struct ether_header *eth;
	dessert_msg_ethdecap(msg, &eth);

	/* hack to get the hardware address */
	if (sysif->flags & _DESSERT_TAP_NOMAC) {
		/* copy from first packet received */
		memcpy(sysif->hwaddr, eth->ether_shost, ETHER_ADDR_LEN);
		dessert_info("guessed hwaddr for %s: %02x:%02x:%02x:%02x:%02x:%02x", sysif->if_name,
				sysif->hwaddr[0], sysif->hwaddr[1], sysif->hwaddr[2],
				sysif->hwaddr[3], sysif->hwaddr[4], sysif->hwaddr[5]);
		/* check whether we need to set defsrc */
		if ((sysif->flags & DESSERT_MAKE_DEFSRC) || memcmp(dessert_l25_defsrc,
				ether_null, ETHER_ADDR_LEN) == 0) {
			memcpy(dessert_l25_defsrc, sysif->hwaddr, ETHER_ADDR_LEN);
			dessert_info("set dessert_l25_defsrc to hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
					dessert_l25_defsrc[0], dessert_l25_defsrc[1],dessert_l25_defsrc[2],
					dessert_l25_defsrc[3], dessert_l25_defsrc[4], dessert_l25_defsrc[5]);
		}
		sysif->flags &= ~_DESSERT_TAP_NOMAC;
	}

	/* unregister me */
	dessert_sysrxcb_del(_dessert_sysif_init_getmachack);

	return DESSERT_MSG_KEEP;
}

/** internal packet processing thread body */
static void *_dessert_sysif_init_thread(void* arg) {

	dessert_sysif_t *sysif = (dessert_sysif_t *) arg;
	size_t len;
	size_t buflen = ETHER_MAX_LEN;
	char buf[buflen];
	dessert_msg_proc_t proc;
	dessert_frameid_t id;
	dessert_sysrxcbe_t *cb;
	int res;
	int ex = 0;
	dessert_sysrxcb_t **cbl = NULL;
	int cbllen = 0;
	int cblcur = -1;
	int cblver = -1;

	while (!ex) {

		memset(buf, 0, buflen);
		if (sysif->flags & DESSERT_TUN) { // read IP datagram from TUN interface
			len = read((sysif->fd), buf + ETHER_HDR_LEN, buflen - ETHER_HDR_LEN);
		} else { // read Ethernet frame from TAP interface
			len = read((sysif->fd), buf, buflen);
		}
		/* Right now the packet has been written to the buffer. The packet is aligned so that
         * the first layer 3 byte is always at the same position independent whether a TUN or 
         * a TAP interface has been used:
         * buf: [Ethernet Header Space][Layer 3 Header]
         */

		if (len == -1) {
			dessert_debug("got %s while reading on %s (fd %d) - is the sys (tun/tap) interface up?", strerror(errno), sysif->if_name, sysif->fd);
			sleep(1);
			continue;
		}

		/* copy callbacks to internal list to release dessert_cfglock before invoking callbacks*/
		pthread_rwlock_rdlock(&dessert_cfglock);
		if (cblver < _dessert_sysrxcblistver) {
			/* callback list changed - rebuild it */
			cbllen = 0;
			for (cb = _dessert_sysrxcblist; cb != NULL; cb = cb->next)
				cbllen++;
			cbl = realloc(cbl, cbllen * sizeof(dessert_sysrxcb_t *));
			if (cbl == NULL && cbllen > 0) {
				dessert_err("failed to allocate memory for internal callback list");
				pthread_rwlock_unlock(&dessert_cfglock);
				return (NULL);
			}

			cblcur = 0;
			for (cb = _dessert_sysrxcblist; cb != NULL; cb = cb->next)
				cbl[cblcur++] = cb->c;

			cblver = _dessert_sysrxcblistver;
		}
		pthread_rwlock_unlock(&dessert_cfglock);

		/* generate frame id */
		id = _dessert_newframeid();

		/* count packet */
		pthread_mutex_lock(&(sysif->cnt_mutex));
		sysif->ipkts++;
		sysif->ibytes += len;
		pthread_mutex_unlock(&(sysif->cnt_mutex));

		/* call the interested */
		res = 0;
		cblcur = 0;
		memset(&proc, 0, DESSERT_MSGPROCLEN);
		dessert_msg_t *msg = NULL;
        if (sysif->flags & DESSERT_TUN) {
            if (dessert_msg_ipencap((uint8_t*) (buf + ETHER_HDR_LEN), len, &msg) < 0) {
              dessert_err("failed to encapsulate ip datagram on host-to-network-pipeline: %s", errno);
            }
        }
        else {
            if (dessert_msg_ethencap((struct ether_header *) buf, len, &msg) < 0) {
              dessert_err("failed to encapsulate ethernet frame on host-to-network-pipeline: %s", errno);
            }
        }
		while (res > DESSERT_MSG_DROP && cblcur < cbllen) {
			res = cbl[cblcur++](msg, len, &proc, sysif, id);
		}
		if (msg != NULL) dessert_msg_destroy(msg);

	}
	dessert_info("stopped reading on %s (fd %d): %s", sysif->if_name, sysif->fd, strerror(errno));

	free(cbl);
	close(sysif->fd);

	return (NULL);
}
