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
    dessert_meshif_t* iface;
    struct mac_entry* prev;
    struct mac_entry* next;
} mac_entry_t;

static mac_entry_t* _dessert_whitelist = NULL;
static mac_entry_t* _dessert_blacklist = NULL;

static mac_entry_t* find_in_list(char* mac, dessert_meshif_t* iface, mac_entry_t* list) {
    mac_entry_t* elt = NULL;
    LL_FOREACH(list, elt) {
        if((elt->iface == NULL || elt->iface == iface)
           && strncmp(elt->mac, mac, 6) == 0) {
            return elt;
        }
    }
    return NULL;
}

static mac_entry_t* wildcard_in_list(mac_entry_t* list) {
    mac_entry_t* elt = NULL;
    LL_FOREACH(list, elt) {
        if(strncmp(elt->mac, "*", 1) == 0) {
            return elt;
        }
    }
    return NULL;
}

/**
 * Find dessert_meshif_t with matching name
 */
static dessert_meshif_t* ifname2iface(char* ifname) {
    dessert_meshif_t* iface;
    bool b = false;
    MESHIFLIST_ITERATOR_START(iface)

    if(strcmp(iface->if_name, ifname) == 0) {
        b = true;
        break;
    }

    MESHIFLIST_ITERATOR_STOP;
    return b ? iface : NULL;
}

#define print_twice(level, cli, ...) \
    { _dessert_log(level, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__); \
      if(cli) { cli_print(cli, __VA_ARGS__); } \
    }

/**
 * Adds a rule to a list
 *
 * @param mac   6 byte MAC address of the src
 * @param iface rx interface; may be NULL to select all interfaces
 * @param list  add rule to this list
 * @param cli   current CLI for printing messages
 *
 * @return true if rule added, else false
 */
bool dessert_filter_rule_add(char* mac, dessert_meshif_t* iface, enum dessert_filter list, struct cli_def* cli) {
    mac_entry_t** cur = NULL;
    mac_entry_t** other = NULL;

    switch(list) {
        case DESSERT_WHITELIST:
            cur = &_dessert_whitelist;
            other = &_dessert_blacklist;
            break;
        case DESSERT_BLACKLIST:
            cur = &_dessert_blacklist;
            other = &_dessert_whitelist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);

    if(find_in_list(mac, iface, *cur)) {
        print_twice(LOG_WARNING, cli, MAC " is already in the list", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    if(find_in_list(mac, iface, *other)) {
        print_twice(LOG_WARNING, cli, MAC " is already in the other list. Please remove it first", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    mac_entry_t* new_entry = malloc(sizeof(mac_entry_t));

    if(new_entry == NULL) {
        print_twice(LOG_CRIT, cli, "could not allocate memory");
        goto fail;
    }

    memcpy(new_entry->mac, mac, sizeof(new_entry->mac));
    new_entry->iface = iface;

    DL_APPEND(*cur, new_entry);

    pthread_rwlock_unlock(&dessert_filterlock);
    return true;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    return false;
}

/**
 * Removes a rule from a list
 *
 * @param mac   6 byte MAC address of the src
 * @param iface rx interface; may be NULL to select all interfaces
 * @param list  remove rule from this list
 * @param cli   current CLI for printing messages
 *
 * @return true if rule found and removed, else false
 */
bool dessert_filter_rule_rm(char* mac, dessert_meshif_t* iface, enum dessert_filter list, struct cli_def* cli) {
    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t** cur = NULL;

    switch(list) {
        case DESSERT_WHITELIST:
            cur = &_dessert_whitelist;
            break;
        case DESSERT_BLACKLIST:
            cur = &_dessert_blacklist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t* del = find_in_list(mac, iface, *cur);

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

/**
 * CLI command to show all  filter rules
 */
int _dessert_cli_cmd_show_rules(struct cli_def* cli, char* command, char* argv[], int argc) {
    pthread_rwlock_rdlock(&dessert_filterlock);
    mac_entry_t* elt = NULL;
    cli_print(cli, "\nwhitelist");
    cli_print(cli, "-------------------------------------");
    uint16_t i = 0;
    LL_FOREACH(_dessert_whitelist, elt) {
        cli_print(cli, "\t%d\t" MAC ", %s", i, EXPLODE_ARRAY6(elt->mac), elt->iface ? elt->iface->if_name : "*");
        i++;
    }
    cli_print(cli, "\nblacklist");
    cli_print(cli, "-------------------------------------");
    i = 0;
    LL_FOREACH(_dessert_blacklist, elt) {
        cli_print(cli, "\t%d\t" MAC ", %s", i, EXPLODE_ARRAY6(elt->mac), elt->iface ? elt->iface->if_name : "*");
        i++;
    }
    pthread_rwlock_unlock(&dessert_filterlock);
    return CLI_OK;
}

/**
 * CLI command to add a filter rule
 */
int _dessert_cli_cmd_rule_add(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc < 2 || argc > 3) {
        cli_print(cli, "usage: filter add whitelist|blacklist] [MAC] [IFNAME]");
        goto fail;
    }

    char mac[6] = "      ";
    dessert_meshif_t* iface = NULL;
    enum dessert_filter list = -1;

    char* s = "whitelist";

    if(strncmp(s, argv[0], sizeof(s)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        s = "blacklist";

        if(strncmp(s, argv[0], sizeof(s)) == 0) {
            list = DESSERT_BLACKLIST;
        }
        else {
            print_twice(LOG_ERR, cli, "could not parse list: %s", argv[0]);
            goto fail;
        }
    }

    if(sscanf(argv[1], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        if(argv[0] != "*") {
            print_twice(LOG_ERR, cli, "could not parse MAC: %17s", argv[0]);
            goto fail;
        }

        mac[0] = '*';
    }

    if(argc == 2) {
        iface = ifname2iface(argv[2]);
    }

    if(dessert_filter_rule_add(mac, iface, list, cli)) {
        cli_print(cli, "added " MAC " to %s", EXPLODE_ARRAY6(mac), s);
        return CLI_OK;
    }

fail:
    cli_print(cli, "failed to add");
    return CLI_ERROR;
}

/**
 * CLI command to remove a filter rule
 */
int _dessert_cli_cmd_rule_rm(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc < 2) {
        cli_print(cli, "usage: filter rm [whitelist|blacklist] [MAC] [IFNAME]");
        goto fail;
    }

    char mac[6] = "      ";
    dessert_meshif_t* iface = NULL;
    enum dessert_filter list = -1;

    char* s = "whitelist";

    if(strncmp(s, argv[0], sizeof(s)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        s = "blacklist";

        if(strncmp(s, argv[0], sizeof(s)) == 0) {
            list = DESSERT_BLACKLIST;
        }
        else {
            print_twice(LOG_ERR, cli, "could not parse list: %s", argv[0]);
            goto fail;
        }
    }

    if(sscanf(argv[1], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        if(argv[0] != "*") {
            print_twice(LOG_ERR, cli, "could not parse MAC: %17s", argv[0]);
            goto fail;
        }

        mac[0] = '*';
    }

    if(argc == 2) {
        iface = ifname2iface(argv[2]);
    }

    if(dessert_filter_rule_rm(mac, iface, list, cli)) {
        cli_print(cli, "removed " MAC " from %s", EXPLODE_ARRAY6(mac), s);
        return CLI_OK;
    }

fail:
    cli_print(cli, "failed to remove");
    return CLI_ERROR;
}

/**
 * mesh iface callback of the MAC filter
 *
 * Filter frames based on the layer 2 source address and the mesh interface where the frame was received.
 * The rules are checked in the following order:
 * 1) whitelist -> accept
 * 2) blacklist -> drop
 * 3) wildcard -> accept or drop
 * 4) default -> accept
 *
 * Please note that the filter is fairly simple and that the first matching rule is used.
 * Therefore a less specific rule can overwrite a more specific one.
 */
int dessert_mesh_filter(dessert_msg_t* msg, size_t len, dessert_msg_proc_t* proc, dessert_meshif_t* iface, dessert_frameid_t id) {
    char* mac = msg->l2h.ether_shost;

    pthread_rwlock_rdlock(&dessert_filterlock);

    if(find_in_list(mac, iface, _dessert_whitelist)) {
        goto ok;
    }

    if(find_in_list(mac, iface, _dessert_blacklist)) {
        goto drop;
    }

    if(wildcard_in_list(_dessert_whitelist)) {
        goto ok;
    }

    if(wildcard_in_list(_dessert_blacklist)) {
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
