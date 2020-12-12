#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct pcap_pkthdr PacketHeader;

typedef struct {
    u_char DA[6];
    u_char SA[6];
    u_short type;
} EtherInfo;

typedef struct _ArpHeader {
    u_int16_t hwType;
    u_int16_t protocolType;
    u_char hwAddrLen;
    u_char protocolAddrLen;
    u_int16_t opCode;
    u_char sourceHwAddr[6];
    u_char sourceProtocolAddr[4];
    u_char destinationHwAddr[6];
    u_char destinationProtocolAddr[4];
} __attribute((packed)) ArpHeader;

void processPacket(const PacketHeader*, const u_char*);
void printEtherInfo(EtherInfo*);
void printArpHeaderInfo(ArpHeader*);
void dumpcode(const u_char*, int);

int main(int argc, char *argv[]) {
    int res;
    PacketHeader *header;
    const u_char *packet;
    struct bpf_program filter;
    bpf_u_int32 mask = 0;

    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0 ,PCAP_ERRBUF_SIZE);
    if ((device = pcap_lookupdev(errbuf)) == NULL) {
        printf("%s\n", errbuf);
        exit((EXIT_FAILURE));
    }
    printf("Opening device %s\n", device);
    descr = pcap_open_live(device, 2048, 0, 512, errbuf);

    if (pcap_compile(descr, &filter, "arp", 1, mask) == -1) {
        printf("%s\n", pcap_geterr(descr));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(descr, &filter) == -1) {
        printf("%s\n", pcap_geterr(descr));
        exit(EXIT_FAILURE);
    }

    while ((res = pcap_next_ex(descr, &header, &packet)) >= 0) {
        if (res == 0) {
            continue;
        }
        processPacket(header, packet);
    }
    pcap_close(descr);
    return 0;

}

void processPacket(const PacketHeader *header, const u_char *packet) {
    static int cnt = 1;
    printf("Packet Number: %d\n", cnt++);
    EtherInfo *info = (EtherInfo*)packet;
    printEtherInfo(info);
    ArpHeader *arpHeader = (ArpHeader*)(packet + 14);
    printArpHeaderInfo(arpHeader);
    dumpcode(packet, header->len);
}

void printEtherInfo(EtherInfo *info) {
    int i = 0;
    fputs("DA: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%02x", info->DA[i]);
        if (i != 5) putchar(':');
    }
    putchar('\n');
    fputs("SA: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%02x", info->SA[i]);
        if (i != 5) putchar(':');
    }
    putchar('\n');
    printf("Type: 0x%04x\n", ntohs(info->type));
}

void printArpHeaderInfo(ArpHeader *header) {
    int i = 0;
    printf("Hardware Type: %04x\n", ntohs(header->hwType));
    printf("Protocol Type: %04x\n", ntohs(header->protocolType));
    printf("Op Code: %04x\n", ntohs(header->opCode));
    fputs("Source Hwaddr: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%02x", header->sourceHwAddr[i]);
        if (i != 5) putchar(':');
    }
    fputs("\nSource ProtocolAddr: ", stdout);
    for (i = 0; i < 4; i++) {
        printf("%d", header->sourceProtocolAddr[i]);
        if (i != 3) putchar('.');
    }
    fputs("\nDestination Hwaddr: ", stdout);
    for (i = 0; i < 6; i++) {
        printf("%02x", header->destinationHwAddr[i]);
        if (i != 5) putchar(':');
    }
    fputs("\nDestination ProtocolAddr: ", stdout);
    for (i = 0; i < 4; i++) {
        printf("%d", header->destinationProtocolAddr[i]);
        if (i != 3) putchar('.');
    }
    putchar('\n');
    putchar('\n');
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