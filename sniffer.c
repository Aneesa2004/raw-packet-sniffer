#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Function to print MAC address
void print_mac(unsigned char *addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[0], addr[1], addr[2],
           addr[3], addr[4], addr[5]);
}

int main() {
    int sock_raw;
    unsigned char *buffer = (unsigned char *) malloc(65536);

    // Packet counters
    int tcp_count = 0, udp_count = 0, icmp_count = 0;

    // Create raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    printf("Sniffer started...\n");

    while (1) {
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);

        if (data_size < 0) {
            perror("Recvfrom error");
            return 1;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        struct sockaddr_in src, dest;
        src.sin_addr.s_addr = ip->saddr;
        dest.sin_addr.s_addr = ip->daddr;

        printf("\n==============================\n");
        printf("Packet Captured\n");
        printf("==============================\n");

        // MAC
        printf("Source MAC: ");
        print_mac(eth->h_source);
        printf("\n");

        printf("Destination MAC: ");
        print_mac(eth->h_dest);
        printf("\n");

        // IP
        printf("Source IP: %s\n", inet_ntoa(src.sin_addr));
        printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
        printf("TTL: %d\n", ip->ttl);

        // Protocol detection + counting
        if (ip->protocol == 6) {
            printf("Protocol: TCP\n");
            tcp_count++;
        }
        else if (ip->protocol == 17) {
            printf("Protocol: UDP\n");
            udp_count++;
        }
        else if (ip->protocol == 1) {
            printf("Protocol: ICMP\n");
            icmp_count++;
        }
        else {
            printf("Protocol: Other (%d)\n", ip->protocol);
        }

        // TCP details
        if (ip->protocol == 6) {
            struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

            printf("TCP Source Port: %u\n", ntohs(tcp->source));
            printf("TCP Destination Port: %u\n", ntohs(tcp->dest));

            if (ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80)
                printf("Service: HTTP\n");

            if (ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443)
                printf("Service: HTTPS\n");
        }

        // UDP details
        else if (ip->protocol == 17) {
            struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

            printf("UDP Source Port: %u\n", ntohs(udp->source));
            printf("UDP Destination Port: %u\n", ntohs(udp->dest));

            if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53)
                printf("Service: DNS\n");
        }

        // Print counters
        printf("\n--- Packet Counters ---\n");
        printf("TCP: %d | UDP: %d | ICMP: %d\n", tcp_count, udp_count, icmp_count);
    }

    close(sock_raw);
    return 0;
}