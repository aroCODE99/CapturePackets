#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pcap.h>

#define MAX_FLOWS 1000
#define MAX_PACKETS 1000 // Capturing the 1000 packets  

typedef struct {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int packet_count;
    char protocol;
} flowinfo;

flowinfo flows[MAX_FLOWS];

// storing the information about the flows
int flow_count = 0;
int packet_count = 0;
char protocol = 'o';
int tcp_flow = 0;
int udp_flow = 0;
pcap_dumper_t *pcap_dumper; // pcap_dumper_t is a type used for writing packets to a pcap file.

// still don't know what is this doing but just going with the flow
int find_flow_index(const struct in_addr src_ip, const struct in_addr dst_ip, const uint16_t src_port, const uint16_t dst_port)
{
    for (int i = 0; i < flow_count; ++i) {
        if ((flows[i].src_ip.s_addr == src_ip.s_addr && flows[i].dst_ip.s_addr == dst_ip.s_addr &&
             flows[i].src_port == src_port && flows[i].dst_port == dst_port) ||
            (flows[i].src_ip.s_addr == dst_ip.s_addr && flows[i].dst_ip.s_addr == src_ip.s_addr &&
             flows[i].src_port == dst_port && flows[i].dst_port == src_port)) {
            return i;
        }
    }
    return -1;
}

// The thing is that packet is string which is kindof unintuitve
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) 
{
    printf("packed captured!\n");
    printf("timestamp: %ld.%06ld\n", (long)pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec);
    printf("packet length: %d\n", pkthdr->len);
    const struct ethhdr *eth_header = (struct ethhdr*) packet; // start of the Packet is the Ethernet header 
    const struct ip *ip_header = (struct ip*) (packet + sizeof(struct ethhdr)); // then after at the eth_header_size offset, we have
    // ip_header so that's why (packet + sizeof(struct ethhdr))

    char dst_ip[INET_ADDRSTRLEN];
    char src_ip[INET_ADDRSTRLEN];
    
    // FILLING ABOVE BUFFERS
    // inet_ntop - convert IPv4 and IPv6 addresses from binary to text form
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    printf("source ip: %s\n", src_ip);
    printf("destination ip: %s\n", dst_ip);

    if (ip_header->ip_p == IPPROTO_TCP) {
        // The ip_header->ip_hl stores the count of words so we have to convert it in bytes
        const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

        // printing some meta deta
        printf("source port: %d\n", ntohs(tcp_header->th_sport));
        printf("destination port: %d\n", ntohs(tcp_header->th_dport));
        printf("tcp flags: 0x%02x\n", tcp_header-> th_flags);
        printf("protocol: tcp\n");

        // i don't know what this is
        int flow_index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
        if (flow_index == -1) {
			if (flow_count < MAX_FLOWS) {
                flows[flow_count].src_ip = ip_header->ip_src;
                flows[flow_count].dst_ip = ip_header->ip_dst;
                flows[flow_count].src_port = ntohs(tcp_header->th_dport);
                flows[flow_count].dst_port = ntohs(tcp_header->th_sport);
                flows[flow_count].packet_count = 1;
                flows[flow_count].protocol = 'T';
                flow_count += 1;
            } else {
                printf("max flow count reached. cannot add a new flow\n");
            }
        } else {
            flows[flow_index].packet_count += 1;
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // The ip_header->ip_hl stores the count of words so we have to convert it in bytes
        const struct udphdr *udp_header = (struct udphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
        printf("source port: %d\n", ntohs(udp_header->uh_sport));
        printf("destination port: %d\n", ntohs(udp_header->uh_dport));
        printf("protocol: udp\n");
        int flow_index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
        if (flow_index == -1) {
            if (flow_count < MAX_FLOWS) {
                flows[flow_count].src_ip = ip_header->ip_src;
                flows[flow_count].dst_ip = ip_header->ip_dst;
                flows[flow_count].src_port = ntohs(udp_header->uh_sport);
                flows[flow_count].dst_port = ntohs(udp_header->uh_dport);
                flows[flow_count].packet_count = 1;
                flows[flow_count].protocol = 'U';
                flow_count += 1;
            } else {
                printf("max flow count reached. cannot add a new flow\n");
            }
        } else {
            flows[flow_index].packet_count++;
        }
    }

    packet_count += 1;
    printf("\n");
    pcap_dump((char *)pcap_dumper, pkthdr, packet);
    if (packet_count >= MAX_PACKETS) {
        pcap_breakloop((pcap_t *)user_data); // this breaks the pcap_loop
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }
    
    pcap_dumper = pcap_dump_open(handle, "captured_packets.pcap"); // Create the pcap dumper
    if (pcap_dumper == NULL) {
        printf("Error opening pcap file for writing.\n");
        return 1;
    }

    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
    pcap_loop(handle, -1, packet_handler, (unsigned char *)handle);
    pcap_dump_close(pcap_dumper); // Close the pcap dumper
    pcap_close(handle);
    
    for (int k = 0; k < flow_count; k++) {
        if (flows[k].protocol == 'T') {
            tcp_flow += 1;
        }
        else {
            udp_flow += 1;
        }
    }

    // Print flow information
    for (int i = 0; i < flow_count; i++) {
        printf("Flow %d:\n", i + 1);
        printf("Source IP: %s\n", inet_ntoa(flows[i].src_ip));
        printf("Destination IP: %s\n", inet_ntoa(flows[i].dst_ip));
        printf("Port Numbers: %d, %d\n", flows[i].src_port, flows[i].dst_port);
        printf("Packet Count: %d\n", flows[i].packet_count);
        printf("Protocol: %c\n", flows[i].protocol);
        printf("\n");
    }

    // Printing the TCP AND UDP flow count
    printf("Total UDP Flowss: %d\n", udp_flow);
    printf("Total TCP Flows: %d\n", tcp_flow);

    return 0;
}
