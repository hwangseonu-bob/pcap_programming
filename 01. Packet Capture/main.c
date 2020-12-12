#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>

struct Ethernet {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
};

struct IPHeader {
    uint8_t vhl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identifier;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr source;
    struct in_addr destination;
};

void handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
void hexdump(const uint8_t *buf, int len);
void print_mac(const uint8_t mac[]);
void print_ethernet(struct Ethernet eth);
void print_ip_header(struct IPHeader ip);


int main(int argc, char *argv[]) {
    if (argc <= 1) {
        printf("usage: %s <network interface>\n", argv[0]);
        return -1;
    }

    int res = 0;
    char err_buf[PCAP_ERRBUF_SIZE] = {0,};

    pcap_t *desc = NULL;
    const uint8_t *packet = NULL;
    struct pcap_pkthdr *header;

    // device, snaplen, promiscuous mode, to ms, error buf
    desc = pcap_open_live(argv[1], 2048, 1, 512, err_buf);

    if (desc == NULL) {
        fprintf(stderr, "%s\n", err_buf);
        return -1;
    }

    while ((res = pcap_next_ex(desc, &header, &packet)) >= 0) {
        if (res == 0) continue;
        handle_packet(header, packet);
    }

    pcap_close(desc);
    return 0;
}

void handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet) {
    static int cnt = 1;
    printf("Packet Num. %d\n", cnt++);
    struct Ethernet *eth = (struct Ethernet *) packet;
    print_ethernet(*eth);
    if (ntohs(eth->type) == 0x0800) {
        struct IPHeader *ip = (struct IPHeader *) (packet + 14);
        print_ip_header(*ip);
    }
    hexdump(packet, pkthdr->len);
}

void print_mac(const uint8_t mac[]) {
    int i;
    for (i = 0; i < 6; i++) {
        printf("%x", mac[i]);
        if (i != 5) putchar(':');
    }
}

void print_ethernet(struct Ethernet eth) {
    printf("Destination MAC: ");
    print_mac(eth.destination);
    printf("\nSource MAC: ");
    print_mac(eth.source);
    printf("\nType: 0x%04x\n", ntohs(eth.type));
}

void print_ip_header(struct IPHeader ip) {
    char ip_str[20];
    inet_ntop(AF_INET, &(ip.source), ip_str, sizeof(ip_str));
    printf("Source IP: %s\n", ip_str);
    inet_ntop(AF_INET, &(ip.destination), ip_str, sizeof(ip_str));
    printf("Destination IP: %s\n", ip_str);
    printf("TTL: %d\n", ip.ttl);
}

void hexdump(const uint8_t *buf, int len) {
    int i;

    printf("%7s", "offset ");
    for (i = 0; i < 16; i++) {
        printf("%02x ", i);

        if (!(i % 16 - 7))
            printf("- ");
    }
    printf("\n\r");

    for (i = 0; i < len; i++) {
        if (!(i % 16))
            printf("0x%04x ", i);

        printf("%02x ", buf[i]);

        if (!(i % 16 - 7))
            printf("- ");

        if (!(i % 16 - 15)) {
            putchar(' ');
            printf("\n\r");
        }
    }

    putchar('\n');
    putchar('\n');
}