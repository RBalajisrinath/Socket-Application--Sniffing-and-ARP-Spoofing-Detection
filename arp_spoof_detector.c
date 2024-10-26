#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <time.h>

#define MAX_PACKET_SIZE 65536
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_IP_MAC_PAIRS 1000

struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

struct ip_mac_pair {
    unsigned char ip[4];
    unsigned char mac[6];
};

struct ip_mac_pair known_pairs[MAX_IP_MAC_PAIRS];
int pair_count = 0;

void add_ip_mac_pair(unsigned char *ip, unsigned char *mac) {
    if (pair_count < MAX_IP_MAC_PAIRS) {
        memcpy(known_pairs[pair_count].ip, ip, 4);
        memcpy(known_pairs[pair_count].mac, mac, 6);
        pair_count++;
    }
}

int find_ip_mac_pair(unsigned char *ip, unsigned char *mac) {
    for (int i = 0; i < pair_count; i++) {
        if (memcmp(known_pairs[i].ip, ip, 4) == 0) {
            return memcmp(known_pairs[i].mac, mac, 6) == 0;
        }
    }
    return -1; // Not found
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct arp_header *arp_packet = (struct arp_header *) (packet + sizeof(struct ether_header));

    printf("Packet captured at: %s", ctime((const time_t *) &packet_header.ts.tv_sec));
    printf("Packet length: %d\n", packet_header.len);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP packet\n");
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_packet->sender_mac[0], arp_packet->sender_mac[1], arp_packet->sender_mac[2],
               arp_packet->sender_mac[3], arp_packet->sender_mac[4], arp_packet->sender_mac[5]);
        printf("Sender IP: %d.%d.%d.%d\n",
               arp_packet->sender_ip[0], arp_packet->sender_ip[1], arp_packet->sender_ip[2], arp_packet->sender_ip[3]);
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_packet->target_mac[0], arp_packet->target_mac[1], arp_packet->target_mac[2],
               arp_packet->target_mac[3], arp_packet->target_mac[4], arp_packet->target_mac[5]);
        printf("Target IP: %d.%d.%d.%d\n",
               arp_packet->target_ip[0], arp_packet->target_ip[1], arp_packet->target_ip[2], arp_packet->target_ip[3]);

        if (ntohs(arp_packet->opcode) == ARP_REPLY) {
            printf("ARP Reply\n");
            int result = find_ip_mac_pair(arp_packet->sender_ip, arp_packet->sender_mac);
            if (result == 0) {
                printf("Potential ARP spoofing detected!\n");
                // Log the incident
                FILE *log_file = fopen("arp_spoof.log", "a");
                if (log_file) {
                    fprintf(log_file, "Potential ARP spoofing detected at %s", ctime((const time_t *) &packet_header.ts.tv_sec));
                    fprintf(log_file, "Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x, IP: %d.%d.%d.%d\n",
                            arp_packet->sender_mac[0], arp_packet->sender_mac[1], arp_packet->sender_mac[2],
                            arp_packet->sender_mac[3], arp_packet->sender_mac[4], arp_packet->sender_mac[5],
                            arp_packet->sender_ip[0], arp_packet->sender_ip[1], arp_packet->sender_ip[2], arp_packet->sender_ip[3]);
                    fclose(log_file);
                }
            } else if (result == -1) {
                add_ip_mac_pair(arp_packet->sender_ip, arp_packet->sender_mac);
                printf("New IP-MAC pair added to known list\n");
            }
        } else if (ntohs(arp_packet->opcode) == ARP_REQUEST) {
            printf("ARP Request\n");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    dev = argv[1];

    handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    printf("Sniffing on interface %s...\n", dev);

    while ((packet = pcap_next(handle, &packet_header))) {
        print_packet_info(packet, packet_header);
    }

    pcap_close(handle);
    return 0;
}
