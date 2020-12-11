#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>

typedef struct in_addr ipaddr_t;
typedef struct ether_header ether_header_t;
typedef struct icmphdr icmp_header_t;
typedef struct iphdr ip_header_t;

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

u_short ipchecksum(ip_header_t *iph) {
    u_short *iphs = (u_short*)iph;
    u_short len = 20;

    unsigned chksum;

    u_short fianlchk;

    len >>= 1;

    for (int i = 0; i < len; i++) {
        chksum += *iphs++;
    }

    chksum = (chksum >> 16) + (chksum & 0xffff);
    chksum += (chksum >> 16);
    fianlchk = ~chksum & 0xffff;
    return fianlchk;
}

u_short icmp_checksum(const u_short *const data, const size_t byte_sz) {
    if (byte_sz &1) {
        exit(EXIT_FAILURE);
    }

    u_short accu = 0;
    for (size_t i = 0; i < (byte_sz >> 1); i++) {
        accu = accu + data[i];
    }

    while (accu >> 16) {
        accu = (accu & 0xffff) + (accu >> 16);
    }
    const u_short checksum = ~accu;
    return accu;
}

int make_packet(u_char **packet, ipaddr_t my_ip, const u_char *my_mac, ipaddr_t target_ip, const u_char *target_mac) {
    int length = 0;
    ether_header_t eth;
    ip_header_t iph;
    icmp_header_t icmph;

    for (int i = 0; i < 6; ++i) {
        eth.ether_dhost[i] = target_mac[i];
    }
    for (int i = 0; i < 6; ++i) {
        eth.ether_shost[i] = my_mac[i];
    }
    eth.ether_type = htons(ETHERTYPE_IP);
    memcpy(*packet, &eth, sizeof(eth));
    length += sizeof(eth);

    iph.version = 4;
    iph.ihl = 5;
    iph.tos = 0;
    iph.tot_len = htons(42);
    iph.id = getpid();
    iph.frag_off = htons(0x4000);
    iph.ttl = 64;
    iph.protocol = IPPROTO_ICMP;
    iph.check = 0;
    iph.saddr = my_ip.s_addr;
    iph.daddr = target_ip.s_addr;
    iph.check = ipchecksum(&iph);

    memcpy((*packet)+length, &iph, sizeof(iph));
    length += sizeof(iph);

    icmph.type = ICMP_ECHO;
    icmph.code = 0;
    icmph.un.echo.id = getpid();
    icmph.un.echo.sequence = htons(1);
    icmph.checksum = icmp_checksum((u_short*) &icmph, length);

    memcpy((*packet)+length, &icmph, sizeof(icmph));
    length += sizeof(icmph);

    return length;
}

char atoh(const char ascii) {
    if (ascii >= '0' && ascii <= '9') {
        return (char) (ascii - '0');
    }
    else if (ascii >= 'a' && ascii <= 'f') {
        return (char) (10 + ascii - 'a');
    } else {
        return 0;
    }
}

void make_mac_by_str(u_char target[], const char str[]) {
    int i = 0;
    for (i = 0; i < 12; i += 2) {
        target[i / 2] = (u_char) (atoh(str[i]) * 16) + atoh(str[i + 1]);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    int length = 0;
    ipaddr_t my_ip;
    ipaddr_t target_ip;
    u_char my_mac[6];
    u_char target_mac[6];
    u_char  *packet = malloc(sizeof(u_char) * 100);
    pcap_t *desc = NULL;

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if ((device = pcap_lookupdev(errbuf)) == NULL) {
        printf("%s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Opening device %s\n", device);
    desc = pcap_open_live(device, 2048, 0, 512, errbuf);


    get_ip_by_inf(&my_ip, device);
    get_mac_by_inf(my_mac, device);
    make_mac_by_str(target_mac, argv[1]);
    inet_pton(AF_INET, argv[1], &target_ip);

    length = make_packet(&packet, my_ip, my_mac, target_ip, target_mac);

    if (pcap_sendpacket(desc, packet, length) != 0) {
        fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    free(packet);
    pcap_close(desc);
    return 0;
}