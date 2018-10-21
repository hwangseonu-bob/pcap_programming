#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAXBYTES2CAPTURE 2048

typedef struct {
    u_char DA[6];
    u_char SA[6];
    u_short type;
} EtherInfo;

typedef struct {
    u_char VIHL;
    u_char tos;
    u_short totalLength;
    u_short identifier;
    u_short FFO;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    struct in_addr sourceIp;
    struct in_addr destinationIp;
} IpHeader;

void processPacket(const struct pcap_pkthdr*, const u_char*);
void printEtherInfo(EtherInfo*);
void printHeaderInfo(IpHeader*);
void dumpcode(const u_char*, int);

int main(int argc, char *argv[]) {
    int stat = 0;

    struct pcap_pkthdr *header;
    const u_char *packet;

    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    if ((device = pcap_lookupdev(errbuf)) == NULL) {
        printf("%s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    printf("Opening device %s\n", device);
    descr = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, errbuf);
    while((stat = pcap_next_ex(descr, &header, &packet)) >= 0) {
        if (stat == 0) {
            continue;
        }
        processPacket(header, packet);
    }
    pcap_close(descr);
    return 0;
}

void processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int cnt = 1;
    printf("Packet Number: %d\n", cnt++);
    EtherInfo *info = (EtherInfo*)packet;
    printEtherInfo(info);
    if (ntohs(info->type) == 0x0800) {
        IpHeader *header = (IpHeader*)(packet + 14);
        printHeaderInfo(header);
    }
    dumpcode(packet, pkthdr->len);
}

void printEtherInfo(EtherInfo *info) {
    int i = 0;
    fputs("DA: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%x", info->DA[i]);
        if (i != 5) putchar(':');
    }
    putchar('\n');
    fputs("SA: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%x", info->SA[i]);
        if (i != 5) putchar(':');
    }
    putchar('\n');
    printf("Type: 0x%04x\n", ntohs(info->type));
}

void printHeaderInfo(IpHeader *header) {
    char ipStr[20];
    inet_ntop(AF_INET, &(header->sourceIp), ipStr, sizeof(ipStr));
    printf("SIP: %s\n", ipStr);
    inet_ntop(AF_INET, &(header->destinationIp), ipStr, sizeof(ipStr));
    printf("DIP: %s\n", ipStr);
    printf("TTL: %d\n", header->ttl);
}

void dumpcode(const u_char *buf, int len) {
    int i;

    printf("%7s", "offset ");
    for(i=0; i<16;i++){
        printf("%02x ", i);

        if(!(i % 16 -7))
            printf("- ");
    }
    printf("\n\r");

    for(i=0; i<len; i++){
        if(!(i%16))
            printf("0x%04x ", i);

        printf("%02x ", buf[i]);

        if(!(i % 16 - 7))
            printf("- ");

        if(!(i % 16 - 15)){
            putchar(' ');
            printf("\n\r");
        }
    }

    putchar('\n');
    putchar('\n');
}