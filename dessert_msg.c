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


/** creates a new dessert_msg_t and initalizes it.
 * @arg **msgout (out) pointer to return message address
 * @return 0 on success, -errno on error
**/
int dessert_msg_new(dessert_msg_t **msgout) 
{
    dessert_msg_t *msg;
    
    msg = malloc(DESSERT_MAXFRAMEBUFLEN);
    
    if(msg == NULL) {
        dessert_err("faild to allocate buffer for new message!");
        return(-ENOMEM);
    }
    
    memset(msg, 0, DESSERT_MAXFRAMEBUFLEN);
    msg->l2h.ether_type = htons(DESSERT_ETHPROTO);
    memset(msg->l2h.ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(msg->proto, dessert_proto, DESSERT_PROTO_STRLEN);
    msg->ver = dessert_ver;
    msg->ttl = 0xff;
    msg->u8 = 0x00;
    msg->u16 = htons(0xbeef);
    msg->hlen = htons(sizeof(dessert_msg_t));
    msg->plen = htons(0);
    
    *msgout = msg;
    return(DESSERT_OK);
    
}



/** creates a new dessert_msg from an ethernet frame.
 * @arg *eth ethernet frame to encapsuclate
 * @arg len length of the ethernet frame
 * @arg **msgout (out) pointer to return message address
 * @return DESSERT_OK on success, -errno otherwise
**/
int dessert_msg_ethencap(const struct ether_header* eth, size_t eth_len, dessert_msg_t** msgout)
{
    int res;
    dessert_ext_t *ext;
    void *payload;
    
    /* check len */
    if(eth_len > DESSERT_MAXFRAMELEN - DESSERT_MSGLEN + ETHER_HDR_LEN) {
        dessert_debug("failed to encapsulate ethernet frame of %d bytes (max=%d)",
            eth_len, DESSERT_MAXFRAMELEN - DESSERT_MSGLEN + ETHER_HDR_LEN);
        return (-EMSGSIZE);
    }
    
    /* create message */
    res = dessert_msg_new(msgout);
    if(res) {
        return res;
    }
    
    /* add etherheader */
    res = dessert_msg_addext(*msgout, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);
    if(res) {
        return res;
    }
    memcpy(ext->data, eth, ETHER_HDR_LEN);
    
    
    /* copy message */
    dessert_msg_addpayload(*msgout, &payload, (eth_len - ETHER_HDR_LEN));
    memcpy(payload, ((uint8_t *)eth)+ETHER_HDR_LEN, (eth_len - ETHER_HDR_LEN));
    
    return(DESSERT_OK);
}



/** extracts an ethernet frame from a dessert_msg 
 * @arg *msg    pointer to dessert_msg message to decapsulate
 * @arg **ethout (out) pointer to return ethernet message
 * @return eth_len on success, -1 otherwise
**/
int dessert_msg_ethdecap(const dessert_msg_t* msg, struct ether_header** ethout)
{
    dessert_ext_t *ext;
    int res;
    
    /* create message */
    size_t eth_len = ntohs(msg->plen)+ETHER_HDR_LEN;
    *ethout = malloc(eth_len);
    if(*ethout == NULL) {
        return (-1);
    }
    
    /* copy header */
    res = dessert_msg_getext(msg, &ext, DESSERT_EXT_ETH, 0);
    if(res != 1) {
        return (-1);
    }
    memcpy(*ethout, ext->data, ETHER_HDR_LEN);
    
    /* copy message */
    memcpy(((uint8_t *)(*ethout))+ETHER_HDR_LEN, (((uint8_t *)msg)+ntohs(msg->hlen)), ntohs(msg->plen));
    
    
    return(eth_len);
}




/** free a dessert_msg
 * @arg *msg message to free
**/
void dessert_msg_destroy(dessert_msg_t* msg)
{
    free(msg);
}


/** free a dessert_prc_msg
 * @arg *proc processing buffer to free
**/
void dessert_msg_proc_destroy(dessert_msg_proc_t* proc)
{
    free(proc);
}


/** generates a copy of a dessert_msg
 * @arg **msgnew (out) pointer to return message address
 * @arg *msgold pointer to the message to clone
 * @arg sparse whether to allocate DESSERT_MAXFRAMELEN or only hlen+plen
 * @return DESSERT_OK on success, -errno otherwise
**/
int dessert_msg_clone(dessert_msg_t **msgnew, const dessert_msg_t *msgold, uint8_t sparse)
{
    dessert_msg_t *msg;
    size_t msglen = ntohs(msgold->hlen) + ntohs(msgold->plen);

    if(sparse) {
        msg = malloc(msglen);
    } else {
        msg = malloc(DESSERT_MAXFRAMEBUFLEN);
    }
    
    if(msg == NULL) {
        return(-errno);
    }
    
    memcpy(msg, msgold, msglen);

    if(sparse) {
        msg->flags |= DESSERT_FLAG_SPARSE;
    } else {
        msg->flags &= DESSERT_FLAG_SPARSE^DESSERT_FLAG_SPARSE;
    }
    
    *msgnew = msg;
    return(DESSERT_OK);
    
}


/** generates a copy of a dessert_msg_proc
 * @arg **procnew (out) pointer to return message address
 * @arg *procold pointer to the message to clone
 * @return DESSERT_OK on success, -errno otherwise
**/
int dessert_msg_proc_clone(dessert_msg_proc_t **procnew, const dessert_msg_proc_t *procold)
{
    if(procold == NULL) {
        *procnew = procold;
        return(DESSERT_OK);
    }
 
    dessert_msg_proc_t *proc;
    
    proc = malloc(DESSERT_MSGPROCLEN);
    
    if(proc == NULL) {
        return(-errno);
    }
    
    memcpy(proc, procold, DESSERT_MSGPROCLEN);
    
    *procnew = proc;
    return(DESSERT_OK);
    
}


/** checks whether a dessert_msg is consistend
 * @arg msg the message to be checked
 * @arg len the length of the buffer
 * @return  DESSERT_OK on success
 * @return -1 of the message is too large for the buffer
 * @return -2 if the message was not intended to this daemon
 * @return -3 if some extension is not consistent
 * %DESCRIPTION: 
 ***********************************************************************/
int dessert_msg_check(const dessert_msg_t* msg, size_t len)
{
    dessert_ext_t  *ext;
    
    /* is the message large enough to at least carry the header */
    if(len < DESSERT_MSGLEN) {
        dessert_info("message too short - shorter than DESSERT_MSGLEN");
        return (-1);
    }
    if( ntohs(msg->hlen) + ntohs(msg->plen) > len) {
        dessert_info("message too short - shorter than header + payload");
        return (-1);
    }
    
    /* right protocol and version */
    if( msg->proto[0] != dessert_proto[0] ||
        msg->proto[1] != dessert_proto[1] ||
        msg->proto[2] != dessert_proto[2] )
    {
        dessert_info("wrong dessert protocol");
        return (-2);
    }
    if( msg->ver != dessert_ver ) {
        dessert_info("wrong dessert protocol version");
        return (-2);
    }
        
    /* now check extensions.... */
    ext = (dessert_ext_t *)((uint8_t *) msg + DESSERT_MSGLEN);
    while( (uint8_t *)ext < ( (uint8_t *) msg + (size_t) ntohs(msg->hlen) ) )
    {
        /* does current extension fit into the header? */
        if( ( (uint8_t *)ext + (size_t) ext->len  ) > 
            ( (uint8_t *)msg + (size_t) ntohs(msg->hlen) ) )
        {
            dessert_info("extension %x too long", ext->type);
            return (-3);
        }
        if (ext->len < 4) {
            dessert_info("extension %x too short", ext->type);
            return (-3);
        }
        
        ext = (dessert_ext_t *) ( (uint8_t *) ext + (size_t) ext->len);
    }
    
    /* message is valid */
    return DESSERT_OK;
}



/** callback that checks whether a dessert_msg is consistend
 * @arg *msg dessert_msg_t frame recvied
 * @arg len length of ethernet frame recvied
 * @arg *iface interface recvied packet on
 * @return DESSERT_MSG_KEEP if message is valid, DESSERT_MSG_DROP otherwise
**/
int dessert_msg_check_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id)
{
    if(dessert_msg_check(msg, len)) {
        dessert_debug("invalid package - discarding");
        return DESSERT_MSG_DROP;
    }
    return DESSERT_MSG_KEEP;
}

/** dump a desp2_msg to a string
 * @arg *msg the message to be dumped
 * @arg len the length of the buffer
 * @arg *buf text output buffer
 * @arg blen text output buffer length
**/
void dessert_msg_dump(const dessert_msg_t* msg, size_t len, char *buf, size_t blen) {
    dessert_msg_proc_dump(msg, len, NULL, buf, blen);
}


/** dump a desp2_msg to a string
 * @arg *msg the message to be dumped
 * @arg len the length of the buffer
 * @arg *proc the processing buffer
 * @arg *buf text output buffer
 * @arg blen text output buffer length
**/
void dessert_msg_proc_dump(const dessert_msg_t* msg, size_t len, const dessert_msg_proc_t *proc, char *buf, size_t blen)
{
    dessert_ext_t  *ext;
    int extidx = 0;
    int i;
    struct ether_header *l25h;

    #define _dessert_msg_check_append(...) snprintf(buf+strlen(buf), blen-strlen(buf), __VA_ARGS__)
    memset((void *)buf, 0, blen);

    _dessert_msg_check_append("\tl2_dhost:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
        msg->l2h.ether_dhost[0], msg->l2h.ether_dhost[1], msg->l2h.ether_dhost[2],
        msg->l2h.ether_dhost[3], msg->l2h.ether_dhost[4], msg->l2h.ether_dhost[5]);
    _dessert_msg_check_append("\tl2_shost:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
        msg->l2h.ether_shost[0], msg->l2h.ether_shost[1], msg->l2h.ether_shost[2],
        msg->l2h.ether_shost[3], msg->l2h.ether_shost[4], msg->l2h.ether_shost[5]);
    _dessert_msg_check_append("\tl2_type:   %x\n\n", ntohs(msg->l2h.ether_type));
    
    _dessert_msg_check_append("\tproto:     ");
    strncpy(buf+strlen(buf), msg->proto, DESSERT_PROTO_STRLEN);
    _dessert_msg_check_append("\n\tver:       %d\n", msg->ver);
    
    _dessert_msg_check_append("\tflags:    ");
    if(msg->flags & DESSERT_FLAG_SPARSE)
        _dessert_msg_check_append(" SPARSE");
        
    _dessert_msg_check_append("\n\tttl:  %x\n", (msg->ttl));
    _dessert_msg_check_append("\tu8:  %x\n", (msg->u8));
    _dessert_msg_check_append("\tu16:  %x\n", ntohs(msg->u16));
    _dessert_msg_check_append("\thlen:      %d\n", ntohs(msg->hlen));
    _dessert_msg_check_append("\tplen:      %d\n\n", ntohs(msg->plen));

    /* get l2.5 header if possible */
    if((l25h = dessert_msg_getl25ether(msg)) != NULL) {
        _dessert_msg_check_append("\tl25 proto: ethernet\n");
        
        _dessert_msg_check_append("\tl25_dhost: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            l25h->ether_dhost[0], l25h->ether_dhost[1], l25h->ether_dhost[2],
            l25h->ether_dhost[3], l25h->ether_dhost[4], l25h->ether_dhost[5]);
        _dessert_msg_check_append("\tl25_shost: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            l25h->ether_shost[0], l25h->ether_shost[1], l25h->ether_shost[2],
            l25h->ether_shost[3], l25h->ether_shost[4], l25h->ether_shost[5]);
        _dessert_msg_check_append("\tl25_type:  %x\n\n", ntohs(l25h->ether_type));
        
    }
    
    /* we have a trace */
    if(dessert_msg_trace_dump(msg, buf, blen-strlen(buf)) >1)
        _dessert_msg_check_append("\n");
    
    /* now other extensions.... */
    ext = (dessert_ext_t *)((uint8_t *) msg + DESSERT_MSGLEN);
    while( (uint8_t *)ext < ( (uint8_t *) msg + (size_t) ntohs(msg->hlen) ) )
    {
        _dessert_msg_check_append("\textension %d:\n", extidx);
       
        /* does current extension fit into the header? */
        if((( (uint8_t *)ext + (size_t) ext->len  ) > 
            ( (uint8_t *)msg + (size_t) ntohs(msg->hlen) ) ) ||
           (  ext->len < 4))
        {
            _dessert_msg_check_append("\t\tbroken extension - giving up!\n");
            break;
        }
        
        _dessert_msg_check_append("\t\ttype:      0x%02x\n", ext->type);
        _dessert_msg_check_append("\t\tlen:       %d\n", ext->len);
        
        if(ext->type != DESSERT_EXT_ETH &&
           ext->type != DESSERT_EXT_TRACE  ) {
            _dessert_msg_check_append("\t\tdata:      ");
            for(i=0; i < dessert_ext_getdatalen(ext); i++) {
                _dessert_msg_check_append("0x%x ", ext->data[i]);
                if (i%12 == 1 && i != 1)
                    _dessert_msg_check_append("\t\t           ");
            }
        }
        _dessert_msg_check_append("\n");
        
        ext = (dessert_ext_t *) ( (uint8_t *) ext + (size_t) ext->len);
        extidx++;
    }
    
    if(proc != NULL) {
        _dessert_msg_check_append("\tlocal processing header:\n");
        _dessert_msg_check_append("\tlflags:    ");
        
        if(proc->lflags & DESSERT_LFLAG_SRC_SELF)
            _dessert_msg_check_append(" DESSERT_FLAG_SRC_SELF");
        if(proc->lflags & DESSERT_LFLAG_DST_SELF)
            _dessert_msg_check_append(" DESSERT_FLAG_DST_MULTICAST");
        if(proc->lflags & DESSERT_LFLAG_DST_MULTICAST)
            _dessert_msg_check_append(" DESSERT_FLAG_DST_SELF");
        if(proc->lflags & DESSERT_LFLAG_DST_BROADCAST)
            _dessert_msg_check_append(" DESSERT_FLAG_DST_BROADCAST");
        if(proc->lflags & DESSERT_LFLAG_PREVHOP_SELF)
            _dessert_msg_check_append(" DESSERT_FLAG_PREVHOP_SELF");
        if(proc->lflags & DESSERT_LFLAG_NEXTHOP_SELF)
            _dessert_msg_check_append(" NEXTHOP_SELF");
        if(proc->lflags & DESSERT_LFLAG_NEXTHOP_BROADCAST)
            _dessert_msg_check_append(" NEXTHOP_BROADCAST");
    }    

}


/** dump a desp2_msg to debug log
 * @arg *msg dessert_msg_t frame recvied
 * @arg len length of ethernet frame recvied
 * @arg *iface interface recvied packet on
 * ®return DESSERT_MSG_KEEP always
**/
int dessert_msg_dump_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id)
{
    char buf[1024];
    
    dessert_msg_proc_dump(msg, len, proc, buf, 1024);
    dessert_debug("recvied frame #%lu on interface %s - dump:\n%s", (unsigned long) id, iface->if_name, buf);
  
    return DESSERT_MSG_KEEP;
}



/** add an extension record to a dessert_msg
 * @arg *msg  the message the extension sould be added to
 * @arg **ext (out) the extension pointer to the reserved extension space
 * @arg type the type of the externsion
 * @arg len  the length of the ext data (without 2 byte extension header)
 * @return DESSERT_OK on success,
**/
int dessert_msg_addext(dessert_msg_t *msg, dessert_ext_t **ext, uint8_t type, size_t len) 
{
    
    /* check if sparse message */
    if((msg->flags & DESSERT_FLAG_SPARSE) >0) {
        dessert_debug("tried to add extension to a sparse message - use dessert_msg_clone() first!");
        return -1;
    }
    
    /* add DESSERT_EXTLEN to len for convinience*/
    len += DESSERT_EXTLEN;
    
    /* check ext */
    if(len > DESSERT_MAXFRAMELEN - ntohs(msg->hlen) - ntohs(msg->plen)) {
        dessert_debug("message would be too large after adding extension!");
        return -2; /* too big */
    } else if(len < DESSERT_EXTLEN) {
        dessert_debug("extension too small!");
        return -3; /* too small */
    } else if(len > 255) {
        dessert_debug("extension too big!");
        return -2; /* too big */
    }
    
    
    /* move payload if neccessary */
    if(ntohs(msg->plen)>0) {
        memmove( ((uint8_t *)msg + ntohs(msg->hlen) + len), ((uint8_t *)msg + ntohs(msg->hlen)), ntohs(msg->plen));
    }
    
    /* get ext addr */
    *ext = (dessert_ext_t *) ((uint8_t *)msg + ntohs(msg->hlen));
    
    /* update msg hlen */
    msg->hlen = htons(ntohs(msg->hlen) + len);
    
    /* copy in extension data */
    (*ext)->len = len;
    (*ext)->type = type;
    
    return DESSERT_OK;
}

/** remove an extension record from a dessert_msg
 * @arg *msg  the message the extension sould be added to
 * @arg *ext (out) the extension pointer to the extension to be removed
 * @return DESSERT_OK on success,
**/
int dessert_msg_delext(dessert_msg_t *msg, dessert_ext_t *ext) 
{
    
    /* check ext */
    if( (((uint8_t *) ext) <  ((uint8_t *) msg)) ||
        (((uint8_t *) ext) > (((uint8_t *) msg) + ntohs(msg->hlen))) )
    {
        dessert_debug("extension not within packet header - won't remove");
        return DESSERT_ERR;
    }
    
    msg->hlen = htons(ntohs(msg->hlen) - ext->len);
 
    memmove(ext, ((uint8_t *) ext) + ext->len, (ntohs(msg->hlen) + ntohs(msg->plen)) - (((uint8_t *) ext) - ((uint8_t *) msg)) );
    
    return DESSERT_OK;
    
}

/** add or replace payload to a dessert_msg
 * @arg *msg the message the payload sould be added to
 * @arg **payload (out) the pointer to place the payload
 * @arg len the length of the payload
 * @return DESSERT_OK on success, DESSERT_ERR otherwise
**/
int dessert_msg_addpayload(dessert_msg_t* msg, void** payload, int len)
{
    /* check payload */
    if(len > DESSERT_MAXFRAMELEN - ntohs(msg->hlen)) {
        return DESSERT_ERR; /* too big */
    }
    
    /* export payload pointer */
    *payload = ((uint8_t *)msg + ntohs(msg->hlen));
    msg->plen = htons(len);
    
    return DESSERT_OK;
}



/** get an specific or all extensions
 * 
 * @arg *msg the message 
 * @arg **ext (out) pointer to extracted extension
 *                  sets *ext=NULL if  extension not found 
 *                  my be NULL in this case only count/existence matters
 * @arg type type of the ext to retive - use DESSERT_EXT_ANY to get any ext
 * @arg index the index if the extension of that type, starting with 0
 * @return  0 if the message has no such extension,
 * @return count of extensions of that type if count > index
 * @return -count of extensions of that type if count <= index
**/
int dessert_msg_getext(const dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, int index)
{
    int i = 0;
    dessert_ext_t *exti;
    
    if(ext != NULL)
        *ext = NULL;
    
    exti = (dessert_ext_t *)((uint8_t *) msg + DESSERT_MSGLEN);
    while( (uint8_t *)exti < ( (uint8_t *) msg + (size_t) ntohs(msg->hlen) ) )
    {
        /* does current extension fit into the header? */
        if ( type == exti->type || type == DESSERT_EXT_ANY) {
            if ( i == index && ext != NULL) {
                *ext = exti;
            }
            i++;
        }
        exti = (dessert_ext_t *) ( ((uint8_t *) exti) + (size_t) exti->len);
    }
    
    if (i <= index ) {
        i = -i;
    }
    return(i);
    
}



/** get the ether_header sent as DESSERT_EXT_ETH in a dessert_msg
 * @arg *msg the message
 * @return pointer to ether_header data, NULL if DESSERT_EXT_ETH not present
**/
struct ether_header* dessert_msg_getl25ether (const dessert_msg_t* msg) {
    dessert_ext_t  *ext;
    struct ether_header *l25h;
    int res;

    res = dessert_msg_getext(msg, &ext, DESSERT_EXT_ETH, 0);
    if(res != 1) {
        l25h = NULL;
    } else {
        l25h = (struct ether_header *) ext->data;
    }
    
    return l25h;
}



/** check if the message carries a trace extension and add the current trace info
 * if iface is NULL, the packet iss ignored
 * @arg *msg dessert_msg_t frame recvied
 * @arg len length of ethernet frame recvied
 * @arg *iface interface recvied packet on
 * ®return DESSERT_MSG_KEEP always
**/
int dessert_msg_trace_cb(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, const dessert_meshif_t *iface, dessert_frameid_t id)
{
    dessert_ext_t  *ext;
    
    /* abort if message has no trace extension */
    if(dessert_msg_getext(msg, &ext, DESSERT_EXT_TRACE, 0) == 0)
        return DESSERT_MSG_KEEP;

    /* abort if iface is NULL */
    if(iface == NULL)
        return DESSERT_MSG_KEEP;
    
    /* we cannot add header to sparse messages */
    if(msg->flags & DESSERT_FLAG_SPARSE)
        return DESSERT_MSG_NEEDNOSPARSE;
    
    /* get the trace mode (hop vs interface) */
    if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_HOST) {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_TRACE, DESSERT_MSG_TRACE_HOST);
        memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);
    } else if (dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_TRACE, DESSERT_MSG_TRACE_IFACE);
        memcpy((ext->data),                  dessert_l25_defsrc, ETHER_ADDR_LEN);
        memcpy((ext->data)+ETHER_ADDR_LEN,   iface->hwaddr, ETHER_ADDR_LEN);
        memcpy((ext->data)+ETHER_ADDR_LEN*2, msg->l2h.ether_shost, ETHER_ADDR_LEN);
    } else {
        dessert_warn("got packet with %d bytes trace extension - ignoring");
    }
    return DESSERT_MSG_KEEP;
}



/** add inital trace header to dessert message
 * @arg *msg dessert_msg_t message used for tracing
 * @arg mode trace mode
 *           use DESSERT_MSG_TRACE_HOST to only recod default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * ®return DESSERT_OK on success
**/
int dessert_msg_trace_initiate(dessert_msg_t* msg, int mode)
{
    
    dessert_ext_t  *ext;
    struct ether_header *l25h;
    
    if (mode != DESSERT_MSG_TRACE_HOST && mode != DESSERT_MSG_TRACE_IFACE)
        return EINVAL;
    
    if(msg->flags & DESSERT_FLAG_SPARSE)
        return DESSERT_MSG_NEEDNOSPARSE;
    
    dessert_msg_addext(msg, &ext, DESSERT_EXT_TRACE, mode);
    memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);
    if(mode == DESSERT_MSG_TRACE_IFACE) {
        memcpy((ext->data)+ETHER_ADDR_LEN, msg->l2h.ether_shost, ETHER_ADDR_LEN);
        l25h = dessert_msg_getl25ether(msg);
        if(l25h == NULL) {
            memcpy((ext->data)+ETHER_ADDR_LEN, ether_null, ETHER_ADDR_LEN);
        } else {
            memcpy((ext->data)+ETHER_ADDR_LEN*2, l25h->ether_shost, ETHER_ADDR_LEN);
        }
    }
    
    return DESSERT_OK;
    
}

/** dump packet trace to string
 * @arg *msg dessert_msg_t message used for tracing
 * @arg *buf char buffer to place string
 *           use DESSERT_MSG_TRACE_HOST to only recod default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * ®return length of the string - 0 if msg has no trace header
**/
int dessert_msg_trace_dump(const dessert_msg_t* msg, char* buf, int blen)
{
    
    dessert_ext_t  *ext;
    int x, i =0;
    
    #define _dessert_msg_trace_dump_append(...) snprintf(buf+strlen(buf), blen-strlen(buf), __VA_ARGS__)
    
    x = dessert_msg_getext(msg, &ext, DESSERT_EXT_TRACE, 0);
    if(x<1)
        return 0;
    
    _dessert_msg_trace_dump_append("\tpacket trace:\n");
    _dessert_msg_trace_dump_append("\t\tfrom %02x:%02x:%02x:%02x:%02x:%02x\n", 
        ext->data[0], ext->data[1], ext->data[2],
        ext->data[3], ext->data[4], ext->data[5]);
        
    if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
        _dessert_msg_trace_dump_append("\t\t  recvied on   %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ext->data[6], ext->data[7], ext->data[8],
            ext->data[9], ext->data[10], ext->data[11]);
        _dessert_msg_trace_dump_append("\t\t  l2.5 src     %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ext->data[12], ext->data[13], ext->data[14],
            ext->data[15], ext->data[16], ext->data[17]);
    }
        
    for(i=1; i<x; i++) {
        dessert_msg_getext(msg, &ext, DESSERT_EXT_TRACE, i);
        _dessert_msg_trace_dump_append("\t\t#%3d %02x:%02x:%02x:%02x:%02x:%02x\n", i,
            ext->data[0], ext->data[1], ext->data[2],
            ext->data[3], ext->data[4], ext->data[5]);

        if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
            _dessert_msg_trace_dump_append("\t\t  recvied from  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                ext->data[12], ext->data[13], ext->data[14],
                ext->data[15], ext->data[16], ext->data[17]);
            _dessert_msg_trace_dump_append("\t\t  recvie iface  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                ext->data[6], ext->data[7], ext->data[8],
                ext->data[9], ext->data[10], ext->data[11]);
        }
    }
    
    return strlen(buf);
    
}
