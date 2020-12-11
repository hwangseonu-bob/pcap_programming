#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>

#define MAXBYTES2CAPTURE 2048

int get_mac_by_inf(u_char mac[6], const char *dev){
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0){
        printf("can't get MAC Address\n");
        close(fd);
        return 0;
    }

    for (int i = 0; i < 6; ++i){
        mac[i] = (u_char) ifr.ifr_addr.sa_data[i];
    }

    close(fd);
    return 1;
}

int get_ip_by_inf(struct in_addr* ip, const char *dev){
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in *sin;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

    if(ioctl(fd, SIOCGIFADDR, &ifr) != 0){
        printf("can't get IP Address\n");
        close(fd);
        return 0;
    }

    close(fd);

    sin = (struct sockaddr_in*) &ifr.ifr_addr;
    *ip = sin->sin_addr;

    return 1;
}

void make_arp_packet(u_char **packet, int *length, int opcode, struct in_addr my_ip, struct in_addr vic_ip, u_char *my_mac, u_char *vic_mac) {
    struct ether_header eth;
    struct ether_arp arp;
    if (opcode == ARPOP_REQUEST) {
        for (int i = 0; i < 6; i++) {
            eth.ether_dhost[i] = 0xff;
        }
    } else {
        for (int i = 0; i < 6; i++) {
            eth.ether_dhost[i] = vic_mac[i];
        }
    }

    for (int i = 0; i < 6; i++) {
        eth.ether_shost[i] = my_mac[i];
    }

    eth.ether_type = htons(ETHERTYPE_ARP);
    memcpy(*packet, &eth, sizeof(eth));
    (*length) += sizeof(eth);

    arp.arp_hrd = htons(0x0001);
    arp.arp_pro = htons(0x0800);
    arp.arp_hln = 0x06;
    arp.arp_pln = 0x04;
    arp.arp_op = htons((u_int16_t)opcode);

    for (int i = 0; i < 6; i++) {
        arp.arp_sha[i] = my_mac[i];
    }

    if (opcode == ARPOP_REPLY) {
        for (int i = 0; i < 6; i++) {
            arp.arp_tha[i] = vic_mac[i];
        }
    } else {
        for (int i = 0; i < 6; i++) {
            arp.arp_tha[i] = 0x00;
        }
    }

    memcpy(arp.arp_spa, &my_ip, sizeof(my_ip));
    memcpy(arp.arp_tpa, &vic_ip, sizeof(vic_ip));

    memcpy((*packet)+(*length), &arp, sizeof(arp));
    (*length) += sizeof(arp);
}


int main(int argc, char *argv[]) {
    int i;
//    struct bpf_program filter;
//    bpf_u_int32 mask = 0;
    pcap_t *desc = NULL;
    char err_buf[PCAP_ERRBUF_SIZE], *device = argv[1];
    u_char *packet = malloc(sizeof(u_char) * 100);
    int length = 0;

    memset(err_buf, 0, PCAP_ERRBUF_SIZE);

//    if ((device = pcap_lookupdev(err_buf)) == NULL) {
//        printf("%s\n", err_buf);
//        exit(EXIT_FAILURE);
//    }

    printf("Opening device %s\n", device);
    desc = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, err_buf);

//    if (pcap_compile(desc, &filter, "arp", 1, mask) == -1) {
//        printf("%s\n", pcap_geterr(desc));
//        exit(EXIT_FAILURE);
//    }
//
//    if (pcap_setfilter(desc, &filter) == -1) {
//        printf("%s\n", pcap_geterr(desc));
//        exit(EXIT_FAILURE);
//    }

    struct in_addr my_ip;
    struct in_addr vic_ip;
    inet_pton(AF_INET, argv[2], &vic_ip);

    u_char my_mac[6];

    get_ip_by_inf(&my_ip, device);
    get_mac_by_inf(my_mac, device);

    make_arp_packet(&packet, &length, ARPOP_REQUEST, my_ip, vic_ip, my_mac, NULL);
    if (pcap_sendpacket(desc, packet, length) != 0) {
        fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }
    free(packet);
    pcap_close(desc);
}
