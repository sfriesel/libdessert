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

pthread_rwlock_t dessert_filterlock = PTHREAD_RWLOCK_INITIALIZER;

typedef struct mac_entry {
    char mac[6];
    struct mac_entry* prev;
    struct mac_entry* next;
} mac_entry_t;

mac_entry_t* whitelist = NULL;
mac_entry_t* blacklist = NULL;

mac_entry_t* _contains(char* mac, mac_entry_t* list) {
    mac_entry_t* elt = NULL;
    LL_FOREACH(list, elt) {
        if(strncmp(elt->mac, mac, 6) == 0) {
            return elt;
        }
    }
    return NULL;
}

#define print_twice(level, cli, ...) \
    { _dessert_log(level, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__); \
      if(cli) { cli_print(cli, __VA_ARGS__); } \
    }

bool dessert_filter_add(char* mac, enum dessert_filter list, struct cli_def *cli) {
    mac_entry_t** cur = NULL;
    mac_entry_t** other = NULL;
    switch(list) {
        case DESSERT_WHITELIST:
            cur = &whitelist;
            other = &blacklist;
            break;
        case DESSERT_BLACKLIST:
            cur = &blacklist;
            other = &whitelist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);
    if(_contains(mac, *cur)) {
        print_twice(LOG_WARNING, cli, MAC " is already in the list", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    if(_contains(mac, *other)) {
        print_twice(LOG_WARNING, cli, MAC " is already in the other list. Please remove it first", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    mac_entry_t* new_entry = malloc(sizeof(mac_entry_t));
    if(new_entry == NULL) {
        print_twice(LOG_CRIT, cli, "could not allocate memory");
        goto fail;
    }
    memcpy(new_entry->mac, mac, sizeof(new_entry->mac));

    DL_APPEND(*cur, new_entry);

    pthread_rwlock_unlock(&dessert_filterlock);
    return true;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    return false;
}

bool dessert_filter_rm(char* mac, enum dessert_filter list, struct cli_def *cli) {
    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t** cur = NULL;
    switch(list) {
        case DESSERT_WHITELIST:
            cur = &whitelist;
            break;
        case DESSERT_BLACKLIST:
            cur = &blacklist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t* del = _contains(mac, *cur);
    if(del == NULL) {
        print_twice(LOG_CRIT, cli, MAC " not found in list", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    LL_DELETE(*cur, del);
    free(del);

    pthread_rwlock_unlock(&dessert_filterlock);
    return true;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    return false;
}

int _dessert_cli_cmd_showfilters(struct cli_def *cli, char *command, char *argv[], int argc) {
    pthread_rwlock_rdlock(&dessert_filterlock);
    mac_entry_t* elt = NULL;
    cli_print(cli, "\nwhitelist");
    cli_print(cli, "-------------------------------------");
    uint16_t i = 0;
    LL_FOREACH(whitelist, elt) {
        cli_print(cli, "\t%d\t" MAC, i, EXPLODE_ARRAY6(elt->mac));
        i++;
    }
    cli_print(cli, "\nblacklist");
    cli_print(cli, "-------------------------------------");
    i = 0;
    LL_FOREACH(blacklist, elt) {
        cli_print(cli, "\t%d\t" MAC, i, EXPLODE_ARRAY6(elt->mac));
        i++;
    }
    pthread_rwlock_unlock(&dessert_filterlock);
    return CLI_OK;
}

int _dessert_cli_cmd_addfilter(struct cli_def *cli, char *command, char *argv[], int argc) {
    if(argc < 2) {
        cli_print(cli, "usage: filter add [MAC] [whitelist|blacklist]");
        goto fail;
    }

    char mac[6];
    if(sscanf(argv[0], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        print_twice(LOG_ERR, cli, "could not parse MAC: %17s", argv[0]);
        goto fail;
    }

    enum dessert_filter list = -1;
    char* s = "whitelist";
    if(strncmp(s, argv[1], sizeof(s)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        s = "blacklist";
        if(list == -1 && strncmp(s, argv[1], sizeof(s)) == 0) {
            list = DESSERT_BLACKLIST;
        }
    }

    if(dessert_filter_add(mac, list, cli)) {
        cli_print(cli, "added " MAC " to %s", EXPLODE_ARRAY6(mac), s);
        return CLI_OK;
    }

fail:
    cli_print(cli, "failed to add");
    return CLI_ERROR;
}

int _dessert_cli_cmd_rmfilter(struct cli_def *cli, char *command, char *argv[], int argc) {
    if(argc < 2) {
        cli_print(cli, "usage: filter rm [MAC] [whitelist|blacklist]");
        goto fail;
    }

    char mac[6];
    if(sscanf(argv[0], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        print_twice(LOG_ERR, cli, "could not parse MAC: %17s", argv[0]);
        goto fail;
    }

    enum dessert_filter list = -1;
    char* s = "whitelist";
    if(strncmp(s, argv[1], sizeof(s)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        s = "blacklist";
        if(list == -1 && strncmp(s, argv[1], sizeof(s)) == 0) {
            list = DESSERT_BLACKLIST;
        }
    }

    if(dessert_filter_rm(mac, list, cli)) {
        cli_print(cli, "removed " MAC " from %s", EXPLODE_ARRAY6(mac), s);
        return CLI_OK;
    }

fail:
    cli_print(cli, "failed to remove");
    return CLI_ERROR;
}

int dessert_mesh_filter(dessert_msg_t* msg, size_t len, dessert_msg_proc_t *proc, dessert_meshif_t *iface, dessert_frameid_t id) {
    char* mac = msg->l2h.ether_shost;

    pthread_rwlock_rdlock(&dessert_filterlock);
    if(_contains(mac, whitelist)) {
        goto ok;
    }

    if(_contains(mac, blacklist)) {
        goto drop;
    }

ok:
    pthread_rwlock_unlock(&dessert_filterlock);
    return DESSERT_MSG_KEEP;

drop:
    dessert_debug("dropped frame from " MAC, EXPLODE_ARRAY6(mac));
    pthread_rwlock_unlock(&dessert_filterlock);
    return DESSERT_MSG_DROP;
}