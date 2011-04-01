
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dessert.h"
#include "dessert_internal.h"
#include <time.h>
#include "iwlib.h"

#define T_MGMT 0x0
#define ST_AUTH 0xB
#define FC_TYPE(fc) (((fc)>\> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc)>\> 4) & 0xF)
#define SIZE_RADIOTAP_FIX 8
#define debug 1
#define packets 100
#define filter 0

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

struct d_list_node{
  struct d_list_node *next;
  struct d_list_node *pre;
  struct d_list_node *up;
  struct d_list_node *down;
  u_char da[16];  // da is the destination device  eg wlan0 wlan1 wlan2 etc...
  u_char sa[6];	 // sa is the source adress (mac adress of the sender)
  u_char* array_pointer;
  time_t* time_array_pointer;
  u_char counter;
};

struct ieee80211_radiotap_header {
    u_char it_version; //1 Byte
    u_char it_pad; //1 Byte
    u_short it_len; //2 Byte
    u_int it_present; //4 Byte
};

struct ath_rx_radiotap_header {
    struct ieee80211_radiotap_header radiotab_header;
    u_int64_t wr_tsft; //8 Byte
    u_int8_t wr_flags; //1 Byte
    u_int8_t wr_rate; // 1 Byte
    u_int16_t wr_chan_freq;
    u_int16_t wr_chan_flags;
    u_int8_t wr_antenna;
    u_int8_t wr_antsignal;
};

const char spaces[] = {8, 1, 1, 2, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2};

struct radiotap_header_opt_fields {
    u_int64_t wr_tsft; //8 Byte
    u_int8_t wr_flags; //1 Byte
    u_int8_t wr_rate; // 1 Byte
    u_int16_t wr_channel;
    u_int8_t wr_fhss;
    u_int8_t wr_ant_signal; //5
    u_int8_t wr_ant_noise;
    u_int16_t wr_lockquality;
    u_int16_t wr_tx_attenuation;
    u_int16_t wr_db_tx_attenuation;
    char wr_dbm_tx_power;
    u_int8_t wr_antenna;
    u_int8_t wr_db_antsignal;
    u_int8_t wr_db_antnoise;
    u_int16_t wr_rx_flags;
};

struct sniff_management {
    u_short fc;
    u_short duration;
    u_char da[6];
    u_char sa[6];
    u_char bssid[6];
    u_short seq_qtrl;
};

int iterator=0;
int array_size_node=10;
int timer_range=3;
int counter_system=0;
u_short status=0;
struct d_list_node* node;
pthread_mutex_t sema1;
pthread_mutex_t sema2;
struct addr_matrix addr_matrix[add_matrix_size];
char matrix_counter=0;


/*
 *	Wireless Tools
 *
 *		Jean II - HPLB 97->99 - HPL 99->04
 *
 * Common subroutines to all the wireless tools...
 *
 * This file is released under the GPL license.
 *     Copyright (c) 1997-2004 Jean Tourrilhes <jt@hpl.hp.com>
 *
 * iw_sockets_open(void) and iw_freq2float(const iwfreq *in) are from wirelesstools
 */
int iw_sockets_open(void) {
    static const int families = AF_INET;
    int sock;

    /* Try all families we support */
    /* Try to open the socket, if success returns it */
    sock = socket(families, SOCK_DGRAM, 0);
    if(sock >= 0)
        return sock;
    return -1;
}


double iw_freq2float(const iwfreq *in) {
    int i;
    double res = (double) in->m;
    for(i = 0; i < in->e; i++) {
        res *= 10;
    }
    return(res);
}

struct radiotap_header_opt_fields parse(const u_char *packet) {
    struct radiotap_header_opt_fields out;
    out.wr_tsft=0;
    out.wr_flags=0;
    out.wr_rate=0;
    out.wr_channel=0;
    out.wr_fhss=0;
    out.wr_ant_signal=0;
    out.wr_ant_noise=0;
    out.wr_lockquality=0;
    out.wr_tx_attenuation=0;
    out.wr_db_tx_attenuation=0;
    out.wr_dbm_tx_power=0;
    out.wr_antenna=0;
    out.wr_db_antsignal=0;
    out.wr_db_antnoise=0;
    out.wr_rx_flags=0;

    struct ieee80211_radiotap_header* radiotap;

    u_int input;
    u_int ausg;
    int i;
    char timer=0;


    radiotap = (struct ieee80211_radiotap_header*) (packet);

    input = radiotap->it_present;

    int temp = 0;
    int j = 0;

    for (i = 0; i < 15; i++) {
        ausg = (input >> (i)) & 0x01;
        if (ausg>0) {
            if(i == 0) {
                u_int64_t *wr_tsft;
                wr_tsft = (u_int64_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_tsft = *wr_tsft;
                temp+=8;
            }
            if(i == 1) {
                u_int8_t *wr_flags;
                wr_flags = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_flags = *wr_flags;
                ++temp;
            }
            if(i == 2) {
                u_int8_t *wr_rate;
                wr_rate = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_rate = *wr_rate;
                ++temp;
            }
            if(i == 3) {
                u_int16_t *wr_channel;
                wr_channel = (u_int16_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_channel = *wr_channel;
                temp+=4;
            }
            if(i == 4) {
                u_int8_t *wr_fhss;
                wr_fhss = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_fhss = *wr_fhss;
                ++temp;
            }
            if(i == 5) {
                u_int8_t *wr_ant_signal;
                wr_ant_signal = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_ant_signal = *wr_ant_signal;
                ++temp;
            }
            if(i == 6) {
                u_int8_t *wr_ant_noise;
                wr_ant_noise = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_ant_noise = *wr_ant_noise;
                ++temp;
            }
            if(i == 7) {
                u_int16_t *wr_lockquality;
                wr_lockquality = (u_int16_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_lockquality = *wr_lockquality;
                temp+=2;
            }
            if(i == 8) {
                u_int16_t *wr_tx_attenuation;
                wr_tx_attenuation = (u_int16_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_tx_attenuation = *wr_tx_attenuation;
                temp+=2;
            }
            if(i == 9) {
                u_int16_t *wr_db_tx_attenuation;
                wr_db_tx_attenuation = (u_int16_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_db_tx_attenuation = *wr_db_tx_attenuation;
                temp+=2;
            }
            if(i == 10) {
                char *wr_dbm_tx_power;
                wr_dbm_tx_power = (char*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_dbm_tx_power = *wr_dbm_tx_power;
                ++temp;
            }
            if(i == 11) {
                u_int8_t *wr_antenna;
                wr_antenna = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_antenna = *wr_antenna;
                ++temp;
            }
            if(i == 12) {
                u_int8_t *wr_db_antsignal;
                wr_db_antsignal = (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_db_antsignal = *wr_db_antsignal;
                ++temp;
            }
            if(i == 13) {
                u_int8_t *wr_db_antnoise;
                wr_db_antnoise= (u_int8_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_db_antnoise= *wr_db_antnoise;
                ++temp;
            }
            if(i == 14) {
                u_int16_t *wr_rx_flags;
                wr_rx_flags = (u_int16_t*) (packet + SIZE_RADIOTAP_FIX + temp);
                out.wr_rx_flags = *wr_rx_flags;
                temp+=2;
            }
        }
    }
    return out;
}

int print_database() {
    if(status == 0) {
        //  printf("STATUS 0 print_db");
        return 0;
    }
    else {
        pthread_mutex_lock(&sema1);
        int i;
        int counter =0;
        struct d_list_node* present_node_vertikal;
        struct d_list_node* present_node_horizontal;
        present_node_vertikal = node; // node is the static global root of the whole database / dynamic matrix
        //vertical level
        while(1==1) {
            present_node_horizontal = present_node_vertikal;
            // horizontal level
            while(1==1){
                cli_print(dessert_cli,"\nDest: %02x:%02x:%02x:%02x:%02x:%02x\t Dev: %s\t RSSI: %d  ",present_node_horizontal->sa[0],
                present_node_horizontal->sa[1],present_node_horizontal->sa[2],present_node_horizontal->sa[3],present_node_horizontal->sa[4],
                present_node_horizontal->sa[5],present_node_horizontal->da, avg_node(present_node_horizontal) );
                if(!present_node_horizontal->next){
                    break;
                }
                present_node_horizontal = present_node_horizontal->next;
            }
            if(!present_node_vertikal->down){
                pthread_mutex_unlock (&sema1);
                return 0;
            }
        present_node_vertikal = present_node_vertikal->down;
        }
    }
}

int avg_node(struct d_list_node* node_temp){
    int j=0;
    int temp1=0;
    int temp2=0;
    int counter=0;

    for(j=0;j<array_size_node;++j) {
        if( (time(NULL) - node_temp->time_array_pointer[j]) <= timer_range){ //operate only is value is not older than time_range
            if(node_temp->array_pointer[j]==0 && counter>0) { //if array is not filled completly
                if(j==0) {// array is complete empty
                    temp2= 0;
                }
                else{ // array is not filled completly
                    temp2 = temp1 / counter;
                }
                return temp2;
            }
            else if( node_temp->array_pointer[j]==0 && counter==0) {
                return 0;
            }
            temp1 += node_temp->array_pointer[j];
            ++counter;
        }
    }
    if(counter==0) {
        return 0;
    }
    temp2= temp1 / (counter);
    return temp2;
}

// deletes a node in the vertical level
int delete(struct d_list_node* present_node_vertikal){
    struct d_list_node* present_node_vertikal_1;
    struct d_list_node* present_node_vertikal_2;

    present_node_vertikal_1 = present_node_vertikal->up;
    present_node_vertikal_2 = present_node_vertikal->down;

    // special procedure for deleting the root node, only if a another node exists
    if(!present_node_vertikal->up && present_node_vertikal->down ){
        node 	= present_node_vertikal->down;
        node->up= NULL;
        free(present_node_vertikal);
        dessert_info("Root Deleting");
        return 0;
    }

    // deletes the last vertical node only if its not the root node
    if(!present_node_vertikal->down && present_node_vertikal->up){
        free(present_node_vertikal);
        present_node_vertikal_1 -> down = NULL;
        return 0;
    }

    // if only root node is in db
    if(!present_node_vertikal->down || !present_node_vertikal->up){
        return 0;
    }

   present_node_vertikal_1->down = present_node_vertikal_2;
   present_node_vertikal_2->up = present_node_vertikal_1;

   free(present_node_vertikal);

   return 0;
}

void maintenance(void* nothing){
    int sum;
    int i;
    int counter =0;

    if(status == 0) {
        //  printf("STATUS 0 print_db");
        return;
    }
    else {
        pthread_mutex_lock(&sema1);
        struct d_list_node* present_node_vertikal;
        struct d_list_node* present_node_horizontal; // = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
        present_node_vertikal = node; // node is the static global root of the whole database / dynamic matrix

        //vertical level
        while(1==1) {
            present_node_horizontal = present_node_vertikal;
            sum=0;
            // horizontal level
            while(1==1){
                sum += avg_node(present_node_horizontal);
                if(!present_node_horizontal->next){
                    if(sum==0){
                        // if all horizontal nodes of a vertical level are too old the level will be deleted
                        delete(present_node_vertikal);
                    }
                    break;
                }
                present_node_horizontal = present_node_horizontal->next;
            }
            if(!present_node_vertikal->down) {
                pthread_mutex_unlock (&sema1);
                return;
            }
            present_node_vertikal = present_node_vertikal->down;
        }
    }
}

void maintenance_start(void* nothing){
    while(1){
        sleep(10);
        maintenance(nothing);
    }
}

void dessert_search_func( u_char sa[6], u_char *dest_dev, void (*function_ptr)(void * mem_ptr, struct d_list_node* node_temp), void * memo_ptr ){	
    if(status == 0){
        return; 
    }	  
    else{
        
        pthread_mutex_lock(&sema1);
        int i;
        int counter =0;
        struct d_list_node* present_node = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
        present_node = node; // node is the static global root of the whole database / dynamic matrix

	// searching in the vertical level
        while(1==1){
	    for(i=0;i<6;i++){
	        if(present_node->sa[i]==sa[i])counter++;
	    } 
	    // vertical matrix level found
	    if(counter==6){
	        counter=0;
	        break;
	    }
	    counter=0;
	    // no vertical matrix level found, build new vertical level
	    if(!present_node->down){
	        pthread_mutex_unlock(&sema1);
	        return;
	    }
	    present_node = present_node->down;
        }
        
        // searching in the horizontal level
        while(1==1){
	    if(strcmp(present_node->da,dest_dev)==0){		      
                (*function_ptr)(memo_ptr, present_node);
                pthread_mutex_unlock(&sema1);
                return;
	    }
	    
	    if(!present_node->next){
	        pthread_mutex_unlock(&sema1);
	        return;
	    }     
	    present_node = present_node->next;
        }
	
    }	
}

int dessert_search_con( u_char sa[6], u_char *dest_dev){
    if(status == 0) {
        // printf("\nSTATUS 0");
        return 0;
    }
    else {
        pthread_mutex_lock(&sema1);
        int i;
        int counter =0;
        struct d_list_node* present_node = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
        present_node = node; // node is the static global root of the whole database / dynamic matrix
        // searching in the vertical level
        while(1==1) {
            for(i=0;i<6;i++){
                if(present_node->sa[i]==sa[i]) {
                    counter++;
                }
            }
            // vertical matrix level found
            if(counter==6) {
                counter=0;
                break;
            }
            counter=0;
            // No vertical matrix level found, build new vertical level
            if(!present_node->down) {
                pthread_mutex_unlock(&sema1);
                return 0;
            }
            present_node = present_node->down;
        }
        // searching in the horizontal level
        while(1==1){
            if(strcmp(present_node->da,dest_dev)==0) {
                pthread_mutex_unlock(&sema1);
                // printf("\nDE LOCK search");
                return avg_node(present_node);
            }
            if(!present_node->next) {
                pthread_mutex_unlock(&sema1);
                return 0;
            }
            present_node = present_node->next;
        }
    }
}

//inserts a value in a node
void insert_value_node(struct d_list_node* node_temp,u_int8_t wr_antsignal){
    node_temp->array_pointer[node_temp->counter]= wr_antsignal;
    node_temp->time_array_pointer[node_temp->counter]= time(NULL);
    if(++node_temp->counter == array_size_node) {
        node_temp->counter=0;
    }
    return;
}

//inserts a value in the matrix
void insert_value(u_char* dest_dev, u_int8_t wr_antsignal,struct sniff_management* management){
    int i;
    int counter =0;
    struct d_list_node* present_node;

    //initial first value in the matrix
    pthread_mutex_lock(&sema1);
    //printf("\nLOCK insert");

    if(status==0) {
        // variable node is the root node in the matrix
        node = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
        // fill root node of the matrix
        bcopy( management->sa, node->sa, 6);
        bcopy( dest_dev, node->da, 16);
        node->array_pointer = (u_char*) calloc (array_size_node,sizeof(u_char));
        node->time_array_pointer = (time_t*) calloc (array_size_node,sizeof(time_t));
        node->counter=0;
        node->up = NULL;
        node->down=NULL;
        node->pre=NULL;
        node->next=NULL;
        insert_value_node(node,wr_antsignal);
        status++;
        pthread_mutex_unlock(&sema1);
        // printf("\nDE LOCK insert");
    }
    else{
        // begin at root node
        present_node = node;
        while(1==1) {
            for(i=0;i<6;i++) {
                if(present_node->sa[i]==management->sa[i]) {
                    counter++;
                }
            }
            //printf("vertical counter: %d \n",counter);
            // vertical matrix level found
            if(counter==6){
            //printf("vertical level found\n");
            //richtige vertikale Ebene gefunden
            counter=0;;
            break;
            }
            counter=0;
            // No vertical matrix level found, build new vertical level
            if(!present_node->down) {
                struct d_list_node* new_node = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
                present_node->down = new_node;
                new_node->up = present_node;
                new_node->pre=NULL;
                new_node->next=NULL;

                bcopy( management->sa, new_node->sa, 6);
                bcopy( dest_dev, new_node->da, 16);

                new_node->array_pointer = (u_char*) calloc (array_size_node,sizeof(u_char));
                new_node->time_array_pointer = (time_t*) calloc (array_size_node,sizeof(time_t));

                new_node->counter=0;
                // insert the wr_antsignal into the node
                insert_value_node(new_node,wr_antsignal);

                counter=0;
                pthread_mutex_unlock(&sema1);
                //  printf("\nDE LOCK insert");
                return;
            }
            present_node = present_node->down;
        }
        // searching in the horizontal level
        while(1==1) {
            if(strcmp(present_node->da,dest_dev)==0){
                //richtige horizontale Ebene gefunden,dann wert einfuegen
                insert_value_node(present_node,wr_antsignal);
                counter=0;
                pthread_mutex_unlock(&sema1);
                //  printf("\nDE LOCK insert");
                break;
            }
            counter=0;
            //insert new node
            if(!present_node->next) {
                struct d_list_node* new_node2;
                    new_node2 = (struct d_list_node*) calloc (1,sizeof(struct d_list_node));
                    present_node->next = new_node2;
                    new_node2->pre = present_node;
                    new_node2->up = NULL;
                    new_node2->down = NULL;
                    bcopy( management->sa, new_node2->sa, 6);
                    bcopy( dest_dev, new_node2->da, 16);
                    new_node2->array_pointer = (u_char*) calloc (array_size_node,sizeof(u_char));
                    new_node2->time_array_pointer = (time_t*) calloc (array_size_node,sizeof(time_t));
                    new_node2->counter=0;
                    insert_value_node(new_node2,wr_antsignal);
                    pthread_mutex_unlock(&sema1);
                    //  printf("\nLOCK insert");
                    break;
            }
            present_node = present_node->next;
            //printf("NEXT node horziontal\n");
        }
    }
    return;
}

char merge_hwaddr(char counter, struct addr_matrix addr_matrix[]){
    char i=0;
    char j=0;
    char timer=0;
    char k=0;
    for(j=0;j<counter;++j) {
        for(i=0;i<counter;++i) {
            if(i!=j) {
                timer=0;
                for(k=0;k<6;++k) {
                    if(addr_matrix[j].addr[k] == addr_matrix[i].addr[k]) {
                        ++timer;
                    }
                }
                if(timer==6) {
                    //checks if hw_addr is related to an interface and a monitor interface
                    if(addr_matrix[i].dev_name[0]=='m' && addr_matrix[i].dev_name[1]=='o' &&
                        addr_matrix[i].dev_name[2]=='n' && addr_matrix[i].dev_name[3]=='i' &&                   addr_matrix[i].dev_name[4]=='_'){
                        bcopy( addr_matrix[j].dev_name, addr_matrix[i].dev_mon_name, 16);
                    }
                }
            }
            else{
                //
            }
        }
    }
    return 0;
}

char get_hwaddr(struct addr_matrix addr_matrix[]) {
    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    char buf[1024];
    int s, i;
    char counter = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) {
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);

    IFR = ifc.ifc_req;
    i=ifc.ifc_len / sizeof(struct ifreq);

    for (i; --i >= 0; IFR++) {
        strcpy(ifr.ifr_name, IFR->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // NO loopback interfaces
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                    bcopy( ifr.ifr_hwaddr.sa_data, addr_matrix[counter].addr, 6);
                    strcpy(addr_matrix[counter].dev_name, IFR->ifr_name);
                    ++counter;
                }
            }
        }
    }
    i=0;

    close(s);
    return counter;
}

void got_packet(u_char *real_dev, const struct pcap_pkthdr *header, const u_char *packet) {
    struct sniff_management* management;
    u_short temp1=0;
    u_short temp2=0;
    u_int i;
    u_int eing;
    struct ieee80211_radiotap_header* radiotap;

    u_int input;
    u_int ausg;
    int bitmask;

    /* define radiotap header */
    radiotap = (struct ieee80211_radiotap_header*) (packet);

    input = radiotap->it_len;

    bitmask = radiotap->it_present;

    struct radiotap_header_opt_fields erg;

    erg = parse(packet);


    int skfd;		/* generic raw socket desc.	*/
    int goterr = 0;
    char * ifname= real_dev;

    /* Create a channel to the NET kernel. */
    if((skfd = iw_sockets_open()) < 0) {
        perror("socket");
        exit(-1);
    }
    struct wireless_config* info;
    struct iwreq wrq;

    info = (struct wireless_config*) calloc (1,sizeof(struct wireless_config));

    if(iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0) {
        /* If no wireless name : no wireless extensions */
        return;
    }
    else {
        strncpy(info->name, wrq.u.name, IFNAMSIZ);
        info->name[IFNAMSIZ] = '\0';
    }

    if(iw_get_ext(skfd, ifname, SIOCGIWFREQ, &wrq) >= 0) {
        info->has_freq = 1;
        info->freq = iw_freq2float(&(wrq.u.freq));
        info->freq_flags = wrq.u.freq.flags;
    }
    info->freq = info->freq/1000000;
    close(skfd);

    if(! (info->freq == erg.wr_channel) ){
    // printf("\nSettingFreq: %f PacketFreq: %d",  info->freq, erg.wr_channel);
        return;
    }
    else{
    }

    free(info);
    management = (struct sniff_management*)(packet + input);
    insert_value(real_dev, erg.wr_ant_signal, management);
    return;
}



void* dessert_monitoring(void* device) {
    pthread_mutex_lock(&sema2);
    // printf("\nSEMA2: LOCK ");
    u_char *dev = (u_char*)malloc(16*sizeof(u_char)); /* capture device name */
    u_char real_dev[16];

    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle; /* packet capture handle */
    char k=0;

    matrix_counter = get_hwaddr(addr_matrix);
    merge_hwaddr(matrix_counter, addr_matrix);
    dev = (u_char *) device;

    for(k=0;k<matrix_counter;++k){
        //dev_mon_name is the name of the real interface from the virtual monitor interface
        if(strcmp(addr_matrix[k].dev_name,dev)==0)bcopy(addr_matrix[k].dev_mon_name , real_dev, 16);
    }

    dessert_info("starting worker thread for monitor interface %s [%s]",dev,real_dev);
    // ignore all ACKS / CTS / RTS allow only managementframes and data-franes
    char filter_exp[] = "type mgt subtype beacon or type data"; /* filter expression [3] */
    struct bpf_program fp; /* compiled filter program (expression) */
        bpf_u_int32 mask; /* subnet mask */
    bpf_u_int32 net; /* ip */

    int num_packets = 0; /* number of packets to capture */

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "%s is not 802.11 device or device is not in monitor mode\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pthread_mutex_unlock(&sema2);
    //    printf("\nSEMA2: DE LOCK ");
    pcap_loop(handle, num_packets, got_packet, real_dev);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

int dessert_monitoring_start(){
    char i=0;
    char j=0;
    char k=0;
    u_char addr[6];

    pthread_t thread[mon_ifs_counter];
    pthread_t thread_maintenance;

    for(i=0;i<mon_ifs_counter;++i){
        pthread_create(&thread[i], NULL, dessert_monitoring, (void *) devString[i]);
    }
    pthread_create(&thread_maintenance, NULL, maintenance_start, NULL);
}
