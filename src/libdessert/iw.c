/*
 * nl80211 userspace tool
 *
 * Copyright 2007, 2008	Johannes Berg <johannes@sipsolutions.net>
 
  strongly customized 2010 by Johannes Klick <johannes.klick@fu-berlin.de>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>                     
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "iw.h"
#include "dessert_internal.h"
#include <dessert.h>

int debug = 0;
int mon_ifs_counter=0;

 /* itoa:  convert n to characters in s */

 /*searches for 802.11 physical interfaces*/
char** phyDevices(){
  
  char** pArrString;
  int i;

  pArrString = (char**)malloc(10*sizeof(char*));
  for (i=0;i<10;i++){
    pArrString[i] = (char*)malloc(10*sizeof(char));
  }
  i = 0;
  DIR *myDir;
  char *dirName="/sys/class/ieee80211";
  struct dirent *entry;
  
  if (!(myDir=opendir(dirName))) {
    dessert_crit("NO PHYs in /sys/class/ieee80211 found.  Check if sysfs is compiled with kernel or wireless devices are already installed.\n");
    return;
 } 
  while (entry=readdir(myDir) )  {
    if(entry->d_name[0]=='p' && entry->d_name[1]=='h'&& entry->d_name[1]=='h' && i < 10 ){
    strcpy(pArrString[++i],entry->d_name);
  }
   // store in pArrstring[0] how much devices have been found 
  sprintf(pArrString[0],"%d",i);
  }
  closedir(myDir);
  return pArrString;
}

static char *mntr_flags[NL80211_MNTR_FLAG_MAX + 1] = {
	NULL,
	"fcsfail",
	"plcpfail",
	"control",
	"otherbss",
	"cook",
};

/* return 0 if not found, 1 if ok, -1 on error */
static int get_if_type(int *argc, char ***argv, enum nl80211_iftype *type)
{
	char *tpstr;

	if (*argc < 2)
		return 0;

	if (strcmp((*argv)[0], "type"))
		return 0;

	tpstr = (*argv)[1];
	*argc -= 2;
	*argv += 2;

	if (strcmp(tpstr, "adhoc") == 0 ||
	    strcmp(tpstr, "ibss") == 0) {
		*type = NL80211_IFTYPE_ADHOC;
		return 1;
	} else if (strcmp(tpstr, "monitor") == 0) {
		*type = NL80211_IFTYPE_MONITOR;
		return 1;
	} else if (strcmp(tpstr, "__ap") == 0) {
		*type = NL80211_IFTYPE_AP;
		return 1;
	} else if (strcmp(tpstr, "__ap_vlan") == 0) {
		*type = NL80211_IFTYPE_AP_VLAN;
		return 1;
	} else if (strcmp(tpstr, "wds") == 0) {
		*type = NL80211_IFTYPE_WDS;
		return 1;
	} else if (strcmp(tpstr, "station") == 0) {
		*type = NL80211_IFTYPE_STATION;
		return 1;
	} else if (strcmp(tpstr, "mp") == 0 ||
			strcmp(tpstr, "mesh") == 0) {
		*type = NL80211_IFTYPE_MESH_POINT;
		return 1;
	}
	dessert_crit( "invalid interface type %s\n", tpstr);
	return -1;
}

static int handle_interface_add(struct nl_cb *cb,
				struct nl_msg *msg,
				int argc, char **argv)
{
	char *name;
	char *mesh_id = NULL;
	enum nl80211_iftype type;
	int tpset;
	if (argc < 1)
		return 1;

	name = argv[0];
	argc--;
	argv++;

	tpset = get_if_type(&argc, &argv, &type);
	if (tpset <= 0)
		return 1;

	if (argc) {
		if (strcmp(argv[0], "mesh_id") != 0)
			return 1;
		argc--;
		argv++;

		if (!argc)
			return 1;
		mesh_id = argv[0];
		argc--;
		argv++;
	}

	if (argc)
		return 1;

	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
	if (tpset)
		NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, type);
	if (mesh_id)
		NLA_PUT(msg, NL80211_ATTR_MESH_ID, strlen(mesh_id), mesh_id);

	return 0;
 nla_put_failure:
	return -ENOBUFS;
}
COMMAND(interface, add, "<name> type <type> [mesh_id <meshid>]",
	NL80211_CMD_NEW_INTERFACE, 0, CIB_PHY, handle_interface_add);
COMMAND(interface, add, "<name> type <type> [mesh_id <meshid>]",
	NL80211_CMD_NEW_INTERFACE, 0, CIB_NETDEV, handle_interface_add);

static int handle_interface_del(struct nl_cb *cb,
				struct nl_msg *msg,
				int argc, char **argv)
{
	return 0;
}
TOPLEVEL(del, NULL, NL80211_CMD_DEL_INTERFACE, 0, CIB_NETDEV, handle_interface_del);

static int print_iface_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFNAME])
		printf("Interface %s\n", nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
	if (tb_msg[NL80211_ATTR_IFINDEX])
		printf("\tifindex %d\n", nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]));
	if (tb_msg[NL80211_ATTR_IFTYPE])
		printf("\ttype %s\n", iftype_name(nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE])));

	return NL_SKIP;
}

static int handle_interface_info(struct nl_cb *cb,
				 struct nl_msg *msg,
				 int argc, char **argv)
{
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_iface_handler, NULL);
	return 0;
}
TOPLEVEL(info, NULL, NL80211_CMD_GET_INTERFACE, 0, CIB_NETDEV, handle_interface_info);

static int handle_interface_set(struct nl_cb *cb,
				struct nl_msg *msg,
				int argc, char **argv)
{
	enum nl80211_mntr_flags flag;
	struct nl_msg *flags;
	int err;

	if (!argc)
		return 1;

	flags = nlmsg_alloc();
	if (!flags) {
		dessert_crit( "failed to allocate flags\n");
		return 2;
	}

	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	while (argc) {
		int ok = 0;
		for (flag = __NL80211_MNTR_FLAG_INVALID + 1;
		     flag < NL80211_MNTR_FLAG_MAX; flag++) {
			if (strcmp(*argv, mntr_flags[flag]) == 0) {
				ok = 1;
				NLA_PUT_FLAG(flags, flag);
				break;
			}
		}
		if (!ok) {
			dessert_crit( "unknown flag %s\n", *argv);
			err = 2;
			goto out;
		}
		argc--;
		argv++;
	}

	nla_put_nested(msg, NL80211_ATTR_MNTR_FLAGS, flags);

	err = 0;
	goto out;
 nla_put_failure:
	err = -ENOBUFS;
 out:
	nlmsg_free(flags);
	return err;
}
COMMAND(set, monitor, "<flag> [...]",
	NL80211_CMD_SET_INTERFACE, 0, CIB_NETDEV, handle_interface_set);

static int handle_interface_meshid(struct nl_cb *cb,
				   struct nl_msg *msg,
				   int argc, char **argv)
{
	char *mesh_id = NULL;

	if (argc != 1)
		return 1;

	mesh_id = argv[0];

	NLA_PUT(msg, NL80211_ATTR_MESH_ID, strlen(mesh_id), mesh_id);

	return 0;
 nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, meshid, "<meshid>",
	NL80211_CMD_SET_INTERFACE, 0, CIB_NETDEV, handle_interface_meshid);


static int handle_name(struct nl_cb *cb,
		       struct nl_msg *msg,
		       int argc, char **argv)
{
	if (argc != 1)
		return 1;

	NLA_PUT_STRING(msg, NL80211_ATTR_WIPHY_NAME, *argv);

	return 0;
 nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, name, "<new name>", NL80211_CMD_SET_WIPHY, 0, CIB_PHY, handle_name);



int mac_addr_a2n(unsigned char *mac_addr, char *arg)
{
	int i;

	for (i = 0; i < ETH_ALEN ; i++) {
		int temp;
		char *cp = strchr(arg, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(arg, "%x", &temp) != 1)
			return -1;
		if (temp < 0 || temp > 255)
			return -1;

		mac_addr[i] = temp;
		if (!cp)
			break;
		arg = cp;
	}
	if (i < ETH_ALEN - 1)
		return -1;

	return 0;
}

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
	"unspecified",
	"IBSS",
	"Station",
	"AP",
	"AP(VLAN)",
	"WDS",
	"Monitor",
	"mesh point"
};

static char modebuf[100];

const char *iftype_name(enum nl80211_iftype iftype)
{
	if (iftype <= NL80211_IFTYPE_MAX)
		return ifmodes[iftype];
	sprintf(modebuf, "Unknown mode (%d)", iftype);
	return modebuf;
}


static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_handle = nl_handle_alloc();
	if (!state->nl_handle) {
		dessert_crit("Failed to allocate netlink handle.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_handle)) {
		dessert_crit("Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl_cache = genl_ctrl_alloc_cache(state->nl_handle);
	if (!state->nl_cache) {
		dessert_crit("Failed to allocate generic netlink cache.\n");
		err = -ENOMEM;
		goto out_handle_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211) {
		dessert_crit( "nl80211 not found.\n");
		err = -ENOENT;
		goto out_cache_free;
	}

	return 0;

 out_cache_free:
	nl_cache_free(state->nl_cache);
 out_handle_destroy:
	nl_handle_destroy(state->nl_handle);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_handle_destroy(state->nl_handle);
}

static void usage(const char *argv0)
{
	struct cmd *cmd;

	dessert_crit( "Usage:\t%s [options] command\n", argv0);
	dessert_crit( "Options:\n");
	dessert_crit( "\t--debug\t\tenable netlink debugging\n");

	dessert_crit("Commands:\n");
	for (cmd = &__start___cmd; cmd < &__stop___cmd; cmd++) {
		switch (cmd->idby) {
		case CIB_NONE:
			/* fall through */
		case CIB_PHY:
			if (cmd->idby == CIB_PHY)
				dessert_crit("\tphy <phyname> ");
			/* fall through */
		case CIB_NETDEV:
			if (cmd->idby == CIB_NETDEV)
				dessert_crit("\tdev <devname> ");
			if (cmd->section)
				dessert_crit("%s ", cmd->section);
			dessert_crit( "%s", cmd->name);
			if (cmd->args)
				dessert_crit(" %s", cmd->args);
			break;
		}
	}
}



static int phy_lookup(char *name)
{
	char buf[200];
	int fd, pos;

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0)
		return -1;
	buf[pos] = '\0';
	return atoi(buf);
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int handle_cmd(struct nl80211_state *state,
		      enum command_identify_by idby,
		      int argc, char **argv)
{
	struct cmd *cmd;
	struct nl_cb *cb = NULL;
	struct nl_msg *msg;
	int devidx = 0;
	int err;
	const char *command, *section;

	if (argc <= 1 && idby != CIB_NONE)
		return 1;

	switch (idby) {
	case CIB_PHY:
	  //iw phy phy3 interface add moni3 type monitor
		devidx = phy_lookup(*argv);
		argc--;
		argv++;
		break;
	case CIB_NETDEV:
		devidx = if_nametoindex(*argv);
		argc--;
		argv++;
		break;
	default:
		break;
	}

	section = command = *argv;
	argc--;
	argv++;

	for (cmd = &__start___cmd; cmd < &__stop___cmd; cmd++) {
		if (cmd->idby != idby)
			continue;
		if (cmd->section) {
			if (strcmp(cmd->section, section))
				continue;
			/* this is a bit icky ... */
			if (command == section) {
				if (argc <= 0)
					return 1;
				command = *argv;
				argc--;
				argv++;
			}
		} else if (section != command)
			continue;
		if (strcmp(cmd->name, command))
			continue;
		if (argc && !cmd->args)
			continue;
		break;
	}

	if (cmd == &__stop___cmd)
		return 1;

	msg = nlmsg_alloc();
	if (!msg) {
		dessert_crit("failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	if (!cb) {
		dessert_crit("failed to allocate netlink callbacks\n");
		err = 2;
		goto out_free_msg;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    cmd->nl_msg_flags, cmd->cmd, 0);

	switch (idby) {
	case CIB_PHY:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
		break;
	case CIB_NETDEV:
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
		break;
	default:
		break;
	}

	err = cmd->handler(cb, msg, argc, argv);
	if (err)
		goto out;

	err = nl_send_auto_complete(state->nl_handle, msg);
	if (err < 0)
		goto out;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	nl_recvmsgs(state->nl_handle, cb);
 out:
	nl_cb_put(cb);
 out_free_msg:
	nlmsg_free(msg);
	return err;
 nla_put_failure:
	dessert_crit("building message failed\n");
	return 2;
}

int configure(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err;
	const char *argv0;

	err = nl80211_init(&nlstate);
	if (err){
	  return -1;
	}

	/* strip off self */
	argc--;
	argv0 = *argv++;

	if (strcmp(*argv, "dev") == 0) {
		argc--;
		argv++;
		err = handle_cmd(&nlstate, CIB_NETDEV, argc, argv);
	} else if (strcmp(*argv, "phy") == 0) {
		argc--;
		argv++;
		err = handle_cmd(&nlstate, CIB_PHY, argc, argv);
	} else
		err = handle_cmd(&nlstate, CIB_NONE, argc, argv);

	if (err == 1)
		usage(argv0);
	if (err < 0){
		dessert_crit("command failed: %s (%d)\n", strerror(-err), err);
		return -1;
		
	}
 out:
	nl80211_cleanup(&nlstate);

	return err;
}

/*creates the monitor devs*/
int _dessert_set_mon()
{
  
    char** cmdString;
    char** argString;
    char* ifconfigString;
    int i,j;
    char buffer [50];

    cmdString = (char**)malloc(10*sizeof(char*));
    ifconfigString = (char*)malloc(32*sizeof(char));	
    for (i=0;i<10;i++){
        cmdString[i] = (char*)malloc(32*sizeof(char));
    }

    argString = phyDevices();
    
    if(argString){
        mon_ifs_counter = atoi(argString[0]);
    }
    else{
        return -1;
    }
      
    char ipnum = 111;
    cmdString[0]="iw";
    cmdString[1]="phy";
    cmdString[3]="interface";
    cmdString[4]="add";
    cmdString[6]="type";
    cmdString[7]="monitor";

    for(i=1;i<=mon_ifs_counter;i++){
        cmdString[2]= argString[i];    
        sprintf(cmdString[5],"moni_%s",argString[i]);			
        sprintf(devString[i-1],"moni_%s",argString[i]); // saves the names of the monitor_interfaces    
        if(configure(8,cmdString)<0){
	  return -1;
	}	  
        sprintf(ifconfigString,"ifconfig moni_%s 192.168.170.%d up",argString[i],++ipnum);
        system(ifconfigString);	
        dessert_info("monitor interface %s has been created",devString[i-1]);
    }
    free(cmdString);
    free(ifconfigString);
    
    return 0;
}
/*deletes the monitor devs*/
int _dessert_del_mon(){
  
    char** cmdString;
    int i,j;
    char buffer [50];
    cmdString = (char**)malloc(4*sizeof(char*));
    for (i=0;i<4;i++){
        cmdString[i] = (char*)malloc(10*sizeof(char));

    }    
    cmdString[0]="iw";	
    cmdString[1]="dev";
    cmdString[3]="del";
    for(i=0;i<mon_ifs_counter;i++){
	cmdString[2]=devString[i];
	if(configure(4,cmdString)<0){
	    return -1;
    }

    }	
    dessert_info("all interfaces closed");
    return 0;
}
  
  




