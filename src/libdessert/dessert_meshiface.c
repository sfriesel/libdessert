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

/* global data storage // P U B L I C */
/* nothing here - yet */

/* global data storage // P R I V A T E */
/* nothing here - yet */

/* local data storage*/
dessert_meshif_t *_dessert_meshiflist = NULL;

pthread_mutex_t _dessert_meshiflist_mutex = PTHREAD_MUTEX_INITIALIZER;
int _dessert_meshiflist_len = 0;
int _dessert_meshiflist_perm_count = 0;
int _dessert_meshiflist_current_perm = 0;
dessert_meshif_t ***_dessert_meshiflist_perms = NULL;

dessert_meshrxcbe_t *_dessert_meshrxcblist;
int _dessert_meshrxcblistver = 0;

/* internal functions forward declarations*/
static void _dessert_packet_process(u_int8_t *args, const struct pcap_pkthdr *header, const u_int8_t *packet);
static void *_dessert_meshif_add_thread(void* arg);
static inline int _dessert_meshsend_if2(dessert_msg_t* msg, dessert_meshif_t *iface);
static void _dessert_meshif_cleanup(dessert_meshif_t *meshif);
static void _dessert_meshiflist_update_permutations(void);
static inline void list2array(dessert_meshif_t *l, dessert_meshif_t **a, int len);
static inline int fact(int i);
static inline void permutation(int k, int len, dessert_meshif_t **a);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/******************************************************************************
 * sending messages
 ******************************************************************************/

/** Sends a \b dessert \b message via the specified interface or all interfaces.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly
 *
 * @param[in] *msgin message to send
 * @param[in] *iface interface to send from - use NULL for all interfaces
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend(const dessert_msg_t* msgin, dessert_meshif_t *iface) {
	dessert_msg_t* msg;
	int res;

	/* check message - we only send valid messages! */
	if (dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
		dessert_warn("will not send invalid message - aborting");
		return EINVAL;
	}

	/* clone message */
	dessert_msg_clone(&msg, msgin, 1);
	res = dessert_meshsend_fast(msg, iface);
	dessert_msg_destroy(msg);

	return res;
}

/** Sends a \b dessert \b message via all interfaces, except via the specified interface.
 *
 * The original message buffer will not be altered, and the ethernet src address will be set correctly.
 *
 * @param[in] *msgin message to send
 * @param[in] *iface interface NOT to send from - use NULL for all interfaces

 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_allbutone(const dessert_msg_t* msgin, dessert_meshif_t *iface) {
	dessert_msg_t* msg;
	int res;

	/* check message - we only send valid messages! */
	if (dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
		dessert_warn("will not send invalid message - aborting");
		return EINVAL;
	}

	/* clone message */
	dessert_msg_clone(&msg, msgin, 1);
	res = dessert_meshsend_fast_allbutone(msg, iface);
	dessert_msg_destroy(msg);

	return res;

}

/** Sends a \b dessert \b message via the interface which is identified by the given hardware address.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly.
 *
 * @param[in] *msgin message to send
 * @param[in] *hwaddr hardware address of the interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_hwaddr(const dessert_msg_t* msgin, const uint8_t hwaddr[ETHER_ADDR_LEN]) {
	dessert_msg_t* msg;
	int res;

	/* check message - we only send valid messages! */
	if (dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
		dessert_warn("will not send invalid message - aborting");
		return EINVAL;
	}

	/* clone message */
	dessert_msg_clone(&msg, msgin, 1);
	res = dessert_meshsend_fast_hwaddr(msg, hwaddr);
	dessert_msg_destroy(msg);

	return res;
}

/** Sends a \b dessert \b message via all interfaces in a randomized fashion.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly.
 *
 * @param[in] *msgin message to send
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_randomized(const dessert_msg_t* msgin) {
	dessert_msg_t* msg;
	int res;

	/* check message - we only send valid messages! */
	if (dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
		dessert_warn("will not send invalid message - aborting");
		return EINVAL;
	}

	/* clone message */
	dessert_msg_clone(&msg, msgin, 1);
	res = dessert_meshsend_fast_randomized(msg);
	dessert_msg_destroy(msg);

	return res;
}

/** Sends a \b dessert \b message fast via the specified interface or all interfaces.
 *
 * This method is faster than dessert_meshsend(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast(dessert_msg_t* msg, dessert_meshif_t *iface) {
	int res = 0;

	/* we have no iface - send on all! */
	if (iface == NULL) {
		pthread_rwlock_rdlock(&dessert_cfglock);
		DL_FOREACH(_dessert_meshiflist, iface) {
			/* set shost */
			memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
			/* send */
			res = _dessert_meshsend_if2(msg, iface);
			if (res) {
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

	return (res);

}

/** Sends a \b dessert \b message fast via all interfaces, except  the specified interface.
 *
 * This method is faster than dessert_meshsend_allbutone(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to NOT send from - use NULL for all interfaces
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_allbutone(dessert_msg_t* msg, dessert_meshif_t *iface) {
	dessert_meshif_t *curr_iface;
	int res = 0;

	/* we have no iface - send on all! */
	if (iface == NULL) {
		pthread_rwlock_rdlock(&dessert_cfglock);
		DL_FOREACH(_dessert_meshiflist, curr_iface) {
			/* set shost */
			memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
			/* send */
			res = _dessert_meshsend_if2(msg, iface);
			if (res) {
				break;
			}
		}
		pthread_rwlock_unlock(&dessert_cfglock);
	} else {
		pthread_rwlock_rdlock(&dessert_cfglock);
		DL_FOREACH(_dessert_meshiflist, curr_iface) {

			/* skip if it is the 'allbutone' interface */
			if (curr_iface == iface) {
				curr_iface = curr_iface->next;
            }

			/* set shost */
			memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
			/* send */
			res = _dessert_meshsend_if2(msg, iface);
			if (res) {
				break;
			}
		}
		pthread_rwlock_unlock(&dessert_cfglock);
	}

	return (res);

}

/** Sends a \b dessert \b message fast via the interface specified by the given
 *  hardware address.
 *
 * This method is faster than dessert_meshsend_hwaddr(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *hwaddr hardware address of the interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_hwaddr(dessert_msg_t* msg, const uint8_t hwaddr[ETHER_ADDR_LEN]) {
	int res;
	dessert_meshif_t *meshif;

	pthread_rwlock_rdlock(&dessert_cfglock);
	DL_FOREACH(_dessert_meshiflist, meshif) {
		if (memcmp(meshif->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0) {
			break;
        }
	}
	pthread_rwlock_unlock(&dessert_cfglock);
	if (likely(meshif != NULL)) {
		/* set shost */
		memcpy(msg->l2h.ether_shost, meshif->hwaddr, ETHER_ADDR_LEN);
		/* send */
		res = _dessert_meshsend_if2(msg, meshif);
	} else {
		dessert_err("No such interface - aborting");
		return ENODEV;
	}

	return (res);
}

/** Sends a \b dessert \b message fast via all interfaces in a randomized fashion.
 *
 * This method is faster than dessert_meshsend_randomized(), but does not check
 * the message and may alter the message buffer.
 *
 * @param[in] *msgin message to send
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_randomized(dessert_msg_t* msgin) {
	int i;
	int res = 0;

	pthread_mutex_lock(&_dessert_meshiflist_mutex);
	for (i = 0; i < _dessert_meshiflist_len; i++) {
		res = dessert_meshsend_fast(msgin,
				_dessert_meshiflist_perms[_dessert_meshiflist_current_perm][i]);
		if (res) {
			break;
		}
	}

	if (_dessert_meshiflist_perm_count > 0) {
		_dessert_meshiflist_current_perm = (_dessert_meshiflist_current_perm
				+ 1) % _dessert_meshiflist_perm_count;
	}
	pthread_mutex_unlock(&_dessert_meshiflist_mutex);

	return res;
}

/** Sends a @b dessert @b message @a msg via the specified interface @a iface or
 *  all interfaces.
 *
 * This method is faster than dessert_meshsend(), but does not check the message
 * and may alter the message buffer. In contrast to dessert_meshsend_fast() it
 * does not write the ether_shost address.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_raw(dessert_msg_t* msg, dessert_meshif_t *iface) {
	int res = 0;

	if (iface == NULL) {
		pthread_rwlock_rdlock(&dessert_cfglock);
		DL_FOREACH(_dessert_meshiflist, iface) {
			res = _dessert_meshsend_if2(msg, iface);
			if (res) {
				break;
			}
		}
		pthread_rwlock_unlock(&dessert_cfglock);
	} else {
		res = _dessert_meshsend_if2(msg, iface);
	}

	return (res);

}

/******************************************************************************
 * meshrx-callback handling
 ******************************************************************************/

/** Removes all occurrences of the given callback function @a c from the meshrx
 *  pipeline.
 *
 * @param[in] c callback function pointer
 *
 * @retval DESSERT_OK  on success
 * @retval DESSERT_ERR otherwise
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshrxcb_del(dessert_meshrxcb_t* c) {
	int count = 0;
	dessert_meshrxcbe_t *i, *last;

	pthread_rwlock_wrlock(&dessert_cfglock);

	if (_dessert_meshrxcblist == NULL) {
		count++;
		goto dessert_meshrxcb_del_out;
	}

	while (_dessert_meshrxcblist->c == c) {
		count++;
		i = _dessert_meshrxcblist;
		_dessert_meshrxcblist = _dessert_meshrxcblist->next;
		free(i);
		if (_dessert_meshrxcblist == NULL) {
			goto dessert_meshrxcb_del_out;
		}
	}

	for (i = _dessert_meshrxcblist; i->next != NULL; i = i->next) {
		if (i->c == c) {
			count++;
			last->next = i->next;
			free(i);
			i = last;
		}
		last = i;
	}

	dessert_meshrxcb_del_out: _dessert_meshrxcblistver++;
	pthread_rwlock_unlock(&dessert_cfglock);
	return ((count > 0) ? DESSERT_OK : DESSERT_ERR);

}

/** Adds a callback function to the meshrx pipeline.
 *
 * The callback going to get called if a packet is received via a dessert interface.
 *
 * @param[in] c    callback function
 * @param[in] prio priority of the function - lower first!
 *
 * @retval DESSERT_OK on success
 * @retval -errno     on error
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio) {
	dessert_meshrxcbe_t *cb, *i;

	cb = (dessert_meshrxcbe_t *) malloc(sizeof(dessert_meshrxcbe_t));
	if (cb == NULL) {
		return (-errno);
    }

	pthread_rwlock_wrlock(&dessert_cfglock);

	cb->c = c;
	cb->prio = prio;
	cb->next = NULL;

	if (_dessert_meshrxcblist == NULL) {
		_dessert_meshrxcblist = cb;
		_dessert_meshrxcblistver++;

		pthread_rwlock_unlock(&dessert_cfglock);
		return DESSERT_OK;
	}

	if (_dessert_meshrxcblist->prio > cb->prio) {
		cb->next = _dessert_meshrxcblist;
		_dessert_meshrxcblist = cb;
		_dessert_meshrxcblistver++;

		pthread_rwlock_unlock(&dessert_cfglock);
		return DESSERT_OK;
	}

	/* find right place for callback */
	for (i = _dessert_meshrxcblist; i->next != NULL && i->next->prio <= cb->prio; i = i->next) {
        ;
    }

	/* insert it */
	cb->next = i->next;
	i->next = cb;
	_dessert_meshrxcblistver++;

	pthread_rwlock_unlock(&dessert_cfglock);
	return DESSERT_OK;
}

/******************************************************************************
 * mesh interface handling
 ******************************************************************************/

/** Returns the head of the list of mesh interfaces (_desert_meshiflist).
 *
 * @retval pointer  if list is not empty
 * @retval NULL     otherwise
 *
 * %DESCRIPTION:
 *
 */
dessert_meshif_t* dessert_meshiflist_get() {
	return _dessert_meshiflist;
}

/** Looks for mesh interface with name @a dev in the list of mesh interfaces and
 *  returns a pointer to it.
 *
 * @param[in] *dev interface name
 *
 * @retval pointer if the interface is found
 * @retval NULL otherwise
 *
 * %DESCRIPTION:
 *
 **/
dessert_meshif_t* dessert_meshif_get_name(const char *dev) {
	dessert_meshif_t *meshif = NULL;

	/* search dev name in iflist */
	//meshif = _dessert_meshiflist;
	pthread_rwlock_rdlock(&dessert_cfglock);
	DL_FOREACH(_dessert_meshiflist, meshif) {
		if (strncmp(meshif->if_name, dev, IF_NAMESIZE) == 0) {
			break;
        }
	}
	pthread_rwlock_unlock(&dessert_cfglock);

	return (meshif);
}

/** Looks for mesh interface with hardware address @a hwaddr in the list of mesh
 *  interfaces and returns a pointer to it.
 *
 * @param[in] *hwaddr interface hardware address
 *
 * @retval pointer if the interface is found
 * @retval NULL otherwise
 *
 * %DESCRIPTION:
 *
 */
dessert_meshif_t* dessert_meshif_get_hwaddr(const uint8_t hwaddr[ETHER_ADDR_LEN]) {
	dessert_meshif_t *meshif = NULL;

	pthread_rwlock_rdlock(&dessert_cfglock);
	DL_FOREACH(_dessert_meshiflist, meshif) {
		if (memcmp(meshif->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0) {
			break;
        }
	}
	pthread_rwlock_unlock(&dessert_cfglock);
	return meshif;
}

/** Removes the corresponding dessert_meshif struct from _dessert_meshiflist and does some cleanup.
 *
 * @param[in] dev interface name to remove from list
 *
 * @retval DESSERT_OK  on success
 * @retval -errno      on error
 *
 * %DESCRIPTION:
 *
 */
int dessert_meshif_del(const char *dev) {
	dessert_meshif_t *meshif;
	//    dessert_meshif_t *meshif_prev; TODO MESHIF_HASH

	/* lock the list */
	pthread_rwlock_wrlock(&dessert_cfglock);
	/* search dev name in iflist */
	DL_FOREACH(_dessert_meshiflist, meshif) {
		if (strncmp(meshif->if_name, dev, IF_NAMESIZE) == 0)
			break;
	}

	if (meshif == NULL) {
		pthread_rwlock_unlock(&dessert_cfglock);
		return (ENODEV);
	}

	/* remove it from list */
	DL_DELETE(_dessert_meshiflist, meshif);
	_dessert_meshiflist_update_permutations();
	pthread_rwlock_unlock(&dessert_cfglock);

	/* tell pcap not to further process packets */
	pcap_breakloop(meshif->pcap);

	/* the remaining cleanup is done in the interface thread *
	 * using _dessert_meshif_cleanup                              */

	return DESSERT_OK;
}

/** Initializes given mesh interface, starts up the packet processor thread.

 * @param[in] *dev interface name
 * @param[in] flags { #DESSERT_IF_PROMISC, #DESSERT_IF_NOPROMISC, #DESSERT_IF_FILTER, #DESSERT_IF_NOFILTER }
 *
 * @retval DESSERT_OK   on success
 * @retval DESSERT_ERR  on error
 *
 *
 *
 * %DESCRIPTION:
 *
 */
int dessert_meshif_add(const char *dev, uint8_t flags) {
	dessert_meshif_t *meshif;

	uint8_t promisc = (flags & DESSERT_IF_NOPROMISC) ? 0 : 1;
	struct bpf_program fp; /* filter program for libpcap */
	char fe[64]; /* filter expression for libpcap */

	snprintf(fe, 64, "ether proto 0x%04x", DESSERT_ETHPROTO);

	/* init new interface entry */
	meshif = (dessert_meshif_t*) malloc(sizeof(dessert_meshif_t));
	if (meshif == NULL) {
		return (-errno);
    }
	memset((void *) meshif, 0, sizeof(dessert_meshif_t));
	strncpy(meshif->if_name, dev, IF_NAMESIZE);
	meshif->if_name[IF_NAMESIZE - 1] = '\0';
	meshif->if_index = if_nametoindex(dev);
	pthread_mutex_init(&(meshif->cnt_mutex), NULL);

	/* check if interface exists */
	if (!meshif->if_index) {
		dessert_err("interface %s - no such interface", meshif->if_name);
		goto dessert_meshif_add_err;
	}

	/* initialize libpcap */
	meshif->pcap = pcap_open_live(meshif->if_name, 2500, promisc, 10, meshif->pcap_err); ///< \todo remove magic number
	if (meshif->pcap == NULL) {
		dessert_err("pcap_open_live failed for interface %s(%d):\n%s", meshif->if_name, meshif->if_index, meshif->pcap_err);
		goto dessert_meshif_add_err;
	}
	if (pcap_datalink(meshif->pcap) != DLT_EN10MB) {
		dessert_err("interface %s(%d) is not an ethernet interface!", meshif->if_name, meshif->if_index);
		goto dessert_meshif_add_err;
	}

	/* pcap filter */
	if (!(flags & DESSERT_IF_NOFILTER)) {
		if (pcap_compile(meshif->pcap, &fp, fe, 0, 0) == -1) {
			dessert_err("couldn't parse filter %s: %s\n", fe, pcap_geterr(meshif->pcap));
			goto dessert_meshif_add_err;
		}
		if (pcap_setfilter(meshif->pcap, &fp) == -1) {
			dessert_err("couldn't install filter %s: %s\n", fe, pcap_geterr(meshif->pcap));
			goto dessert_meshif_add_err;
		}
		/* else { TODO: pcap_freecode() } */
	}

	/* get hardware address */
	if (_dessert_meshif_gethwaddr(meshif) != 0) {
		dessert_err("failed to get hwaddr of interface %s(%d)", meshif->if_name, meshif->if_index);
		goto dessert_meshif_add_err;
	}

	/* check whether we need to set defsrc (default source) */
	if (memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0) {
		memcpy(dessert_l25_defsrc, meshif->hwaddr, ETHER_ADDR_LEN);
		dessert_info("set dessert_l25_defsrc to hwaddr " MAC, EXPLODE_ARRAY6(dessert_l25_defsrc));
	}

	dessert_info("starting worker thread for interface %s(%d) hwaddr" MAC,
			meshif->if_name, meshif->if_index, EXPLODE_ARRAY6(meshif->hwaddr));

	/* start worker thread */
	if (pthread_create(&(meshif->worker), NULL, _dessert_meshif_add_thread,
			(void *) meshif)) {
		dessert_err("creating worker thread failed for interface %s(%d)",
				meshif->if_name, meshif->if_index);
		goto dessert_meshif_add_err;
	}

	/* prepend to interface list */
	pthread_rwlock_wrlock(&dessert_cfglock);
	DL_PREPEND(_dessert_meshiflist, meshif);
	_dessert_meshiflist_update_permutations();
	pthread_rwlock_unlock(&dessert_cfglock);

	return (DESSERT_OK);

dessert_meshif_add_err:

	if (meshif->pcap != NULL) {
		pcap_close(meshif->pcap);
	}
	free(meshif);
	return (DESSERT_ERR);
}

/*****************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/** Run all registered callbacks.
 *
 * @internal
 *
 * @return the return status of the last callback called
 *
 * @warning  Use with care - never register as callback!
 *
 * %DESCRIPTION:
 *
 */
int _dessert_meshrxcb_runall(dessert_msg_t* msg_in, size_t len,
		dessert_msg_proc_t *proc_in, const dessert_meshif_t *meshif,
		dessert_frameid_t id) {
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
	for (cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next) {
		cbllen++;
    }
	cbl = malloc(cbllen * sizeof(dessert_meshrxcb_t *));
	if (cbl == NULL) {
		dessert_err("failed to allocate memory for internal callback list");
		pthread_rwlock_unlock(&dessert_cfglock);
		return DESSERT_MSG_DROP;
	}

	cblcur = 0;
	for (cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next) {
		cbl[cblcur++] = cb->c;
    }

	pthread_rwlock_unlock(&dessert_cfglock);

	/* call the interested */
	res = 0;
	cblcur = 0;
	while (res > DESSERT_MSG_DROP && cblcur < cbllen) {
		_dessert_packet_process_cbagain: res = cbl[cblcur](msg, len, proc, meshif, id);

		if (res == DESSERT_MSG_NEEDNOSPARSE && msg == msg_in) {
			dessert_msg_clone(&msg, msg_in, 0);
			len = dessert_maxlen;
			goto _dessert_packet_process_cbagain;
		} else if (res == DESSERT_MSG_NEEDNOSPARSE && msg != msg_in) {
			dessert_warn("bogus DESSERT_MSG_NEEDNOSPARSE returned from callback!");
		}

		if (res == DESSERT_MSG_NEEDMSGPROC && proc == NULL) {
			proc = malloc(DESSERT_MSGPROCLEN);
			memset(proc, 0, DESSERT_MSGPROCLEN);
			goto _dessert_packet_process_cbagain;
		} else if (res == DESSERT_MSG_NEEDMSGPROC && proc != NULL) {
			dessert_warn("bogus DESSERT_MSG_NEEDMSGPROC returned from callback!");
		}
		cblcur++;
	}
	free(cbl);

    if (msg != msg_in) {
        dessert_msg_destroy(msg);
    }
    if (proc != proc_in) {
        free(proc);
    }

    return (res);
}

/** Get the hardware address of the ethernet device behind meshif.
 *
 * @internal
 *
 * @param *meshif pointer to dessert_meshif_t to query
 *
 * @retval DESSERT_OK on success
 *
 * \warning This is a platform depended function!
 *
 * %DESCRIPTION:
 *
 **/
int _dessert_meshif_gethwaddr(dessert_meshif_t *meshif) {
	/* we need some socket to do that */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct ifreq ifr;
	/* set interface options and get hardware address */
	strncpy(ifr.ifr_name, meshif->if_name, sizeof(ifr.ifr_name));

	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(meshif->hwaddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
		close(sockfd);
		return (DESSERT_OK);
	} else {
		dessert_err("acquiring hwaddr failed");
		close(sockfd);
		return (DESSERT_ERR);
	}
}

/******************************************************************************
 *
 * LOCAL
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/** Function to send packet via a single interface.
 *
 * @internal
 *
 * @param[in] *msg the message to send
 * @param[in] *iface the interface the message should be send via
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL if *iface is NULL
 * @retval EIO if there was a problem sending the message
 *
 * %DESCRIPTION:
 *
 */
static inline int _dessert_meshsend_if2(dessert_msg_t* msg, dessert_meshif_t *iface) {
	int msglen = ntohs(msg->hlen) + ntohs(msg->plen);

	/* check for null meshInterface */
	if (iface == NULL) {
		dessert_err("NULL-pointer given as interface - programming error!");
		return EINVAL;
	}

	/* send packet - temporally setting DESSERT_FLAG_SPARSE */
	uint8_t oldflags = msg->flags;
	msg->flags &= ~DESSERT_FLAG_SPARSE;
	int res = pcap_inject(iface->pcap, (u_int8_t *) msg, msglen);
	msg->flags = oldflags;

	if (res != msglen) {
		if (res == -1) {
			dessert_warn("couldn't send message: %s\n", pcap_geterr(iface->pcap));
		} else {
			dessert_warn("couldn't send message: sent only %d of %d bytes\n",
					res, msglen);
		}
		return (EIO);
	}

	pthread_mutex_lock(&(iface->cnt_mutex));
	iface->opkts++;
	iface->obytes += res;
	pthread_mutex_unlock(&(iface->cnt_mutex));

	return (DESSERT_OK);
}

/** Callback doing the main work for packets received through a dessert interface.
 *
 * @internal
 *
 * @param arg    - meshif-pointer carried by libpcap in something else
 * @param header - pointer to the header by libpcap
 * @param packet - pointer to the packet by libpcap
 *
 * %DESCRIPTION:
 *
 */
static void _dessert_packet_process(u_int8_t *args, const struct pcap_pkthdr *header, const u_int8_t *packet) {
	dessert_meshif_t *meshif = (dessert_meshif_t *) args;
	dessert_msg_t *msg = (dessert_msg_t *) packet;
	size_t len = header->caplen;
	dessert_frameid_t id;
	dessert_msg_proc_t proc;

	/* is it something I understand? */
	if (ntohs(msg->l2h.ether_type) != DESSERT_ETHPROTO) {
		dessert_debug("got packet with ethertype %04x - discarding", ntohs(msg->l2h.ether_type));
		return;
	}

	/* check message */
	if (header->caplen < header->len) {
		dessert_warn("packet too short - check pcap_open_live() parameters");
		return;
	}
	if (header->caplen < DESSERT_MSGLEN) {
		dessert_notice("packet too short - shorter than DESSERT_MSGLEN");
		return;
	}

	/* generate frame id */
	id = _dessert_newframeid();
	memset(&proc, 0, DESSERT_MSGPROCLEN);

	/* count packet */
	pthread_mutex_lock(&(meshif->cnt_mutex));
	meshif->ipkts++;
	meshif->ibytes += header->caplen;
	pthread_mutex_unlock(&(meshif->cnt_mutex));

	_dessert_meshrxcb_runall(msg, len, &proc, meshif, id);
}

/** Internal routine called before interface thread finishes.
 *
 * @internal
 *
 * @param *meshif the interface to be cleaned up
 *
 * %DESCRIPTION:
 *
 */
static void _dessert_meshif_cleanup(dessert_meshif_t *meshif) {
	pcap_close(meshif->pcap);
	free(meshif);
}

/** Internal thread function running the capture loop.
 *
 * @internal
 *
 * @param *arg a void pointer representing a dessert_meshif_t interface
 *
 * %DESCRIPTION:
 */
static void *_dessert_meshif_add_thread(void* arg) {
	dessert_meshif_t *meshif = (dessert_meshif_t *) arg;
	pcap_loop(meshif->pcap, -1, _dessert_packet_process, (u_int8_t *) meshif);
	_dessert_meshif_cleanup(meshif);
	return (NULL);
}

/** Internal function to update the lookup table of permutations of the current _dessert_meshiflist.
 *
 * @internal
 *
 * %DESCRIPTION: \n
 */
static void _dessert_meshiflist_update_permutations() {
	int i, r;

	pthread_mutex_lock(&_dessert_meshiflist_mutex);
	dessert_meshif_t *tmp;
	DL_LENGTH(_dessert_meshiflist, _dessert_meshiflist_len, tmp);

	dessert_meshif_t **a =  calloc(sizeof(a), _dessert_meshiflist_len);
	list2array(_dessert_meshiflist, a, _dessert_meshiflist_len);

	_dessert_meshiflist_perm_count = fact(_dessert_meshiflist_len);

	if (_dessert_meshiflist_perms != NULL) {
		free(_dessert_meshiflist_perms);
	}
	_dessert_meshiflist_perms = calloc(sizeof(dessert_meshif_t **) * _dessert_meshiflist_perm_count + sizeof(dessert_meshif_t *) * _dessert_meshiflist_perm_count * _dessert_meshiflist_len, 1);
	for (i = 0; i < _dessert_meshiflist_perm_count; ++i) {
		_dessert_meshiflist_perms[i]
				= (dessert_meshif_t **) (((char *) _dessert_meshiflist_perms)
						+ sizeof(dessert_meshif_t **)
								* _dessert_meshiflist_perm_count + i
						* _dessert_meshiflist_len * sizeof(dessert_meshif_t *));
	}

	for (r = 0; r < _dessert_meshiflist_perm_count; r++) {
		memcpy(_dessert_meshiflist_perms[r], a, sizeof(dessert_meshif_t *) * _dessert_meshiflist_len);
	}
	free(a);

	for(r = 0; r < _dessert_meshiflist_perm_count; r++){
		permutation(r, _dessert_meshiflist_len, _dessert_meshiflist_perms[r]);
	}

	pthread_mutex_unlock(&_dessert_meshiflist_mutex);
}

/** Internal function to copy the element pointers of the _dessert_meshiflist to an array.
 *
 * @internal
 *
 * @param[in] *l a pointer to the list head
 * @param[out] **a a pointer to an array of dessert_meshif_t
 *
 * %DESCRIPTION: \n
 */
static inline void list2array(dessert_meshif_t *l, dessert_meshif_t **a, int len) {
	dessert_meshif_t *t;
	int i = 0;
	DL_FOREACH(l, t) {
		a[i++] = t;
		if (--len == 0) {
			break;
        }
	}
}

/** Internal function to compute the factorial of a given number.
 *
 * @internal
 *
 * @param[in] i the number
 *
 * @return the factorial
 *
 * %DESCRIPTION: \n
 */
static inline int fact(int i){
    int fact = 1;
    while (i > 0) {
        fact *= i--;
    }
    return fact;
}

/** Internal function to produce a permutation of @a a.
 *
 * @internal
 *
 * @param[in]  k the permutation to generate
 * @param[in]  len the number of elements in the array
 * @param[out] the array to permute
 *
 * @note Algorithm adopted from the Wikipedia article on
 * <a href="http://en.wikipedia.org/wiki/Permutation">Permutations</a>.
 *
 * %DESCRIPTION: \n
 */
static inline void permutation(int k, int len, dessert_meshif_t **a) {
    dessert_meshif_t *temp;
    int j;

    for(j = 2 ; j <= len; j++ ) {
        temp = a[(k%j)];
        a[(k%j)] = a[j-1];
        a[j-1] = temp;
        k = k / j;
    }
}
