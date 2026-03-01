#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <string.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/in.h>

#define MAX_PACKETS 1000

int tcp = 0;
int udp = 0;
int packets_count = 0;

void transportLayerProtocol(int transport_Layer_Protocol, char *buf)
{
    switch ((int) transport_Layer_Protocol) {
    case 6: {
        // in Hex, 24th byte of packet is 06 when it is "TCP"
        tcp += 1;
        snprintf(buf, 4, "%s", "TCP");
        break;
    }
    case 17: {
        // in Hex, 24th byte of packet is 17 when it is "UDP"
        // not going inside of this
        printf("Hello inside of the UDP case\n");
        udp += 1;
        snprintf(buf, 4, "%s", "UDP"); 
        break;
    }
    default: {
        snprintf(buf, sizeof(buf), "%s", "OTHERS"); // in Hex, 24th byte of packet is 17 when it is "UDP"
        break;
    }
    }
}

void linkLayerProtocol(int ethernetType_1, int ethernetType_2, char *buf)
{
    if (ethernetType_1 == 8 && ethernetType_2 == (int)0) {
        // legnth of the IPV4 + '\0' null byte is 5
        snprintf(buf, 5, "%s", "IPV4");
    } else if(ethernetType_1 == (int)134 && ethernetType_2 == (int)221) {
        //in hex 86,converted in decimal 134 & in hex dd,converted in decimal is 221
        snprintf(buf, 5, "%s", "IPV6"); //if ethernet type 0x86dd then ipv4, converted in decimal to manipulate 
    } else {
        snprintf(buf, sizeof(buf), "%s", "OTHERS");
    }
}

void printDetails(unsigned char *buffer)
{
    // getting the type of the ethernet
    int tempEthTypeX = (int)buffer[12]; 		// 13th byte of packet 
 	int tempEthTypeY = (int)buffer[13]; 		// 14th byte of packet
    
    int tempProtocol;
    char str[10]; // max 10 bytes
    char str2[10]; // max 10 bytes
    linkLayerProtocol(tempEthTypeX, tempEthTypeY, str);
    
    if (strcmp(str, "IPV4")) {
        tempProtocol = (int)buffer[23];     // 24th byte of packet is defined transport layer protocol
        transportLayerProtocol(tempProtocol, str2); // getting the transportlayerprotocol
        printf("%s\n", str2);
        if (strcmp(str2, "TCP")) {
            printf("TCP packet woo hoo\n");
        } else if (strcmp(str2, "UDP")) {
            printf("UDP packet woo hoo\n");
        } else {
            printf("other packet\n");
        }
    } else if (strcmp(str, "IPV6")) {
        printf("this is the ipv6 thing\n");
    } else if (strcmp(str, "OTHERS")) {
        printf("other type of internet protocol used\n");
    }
}

int main()
{
    // int socket(int domain, int type, int protocol);
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    unsigned char buf[10000];
    size_t datasize;
    int number_of_packets = 1;
    
    struct sockaddr *sock_addr;
    if (raw_sock < 0) {
        fprintf(stderr, "Error opening the raw socket: %s\n", strerror(errno));
        return 1; 
    }

    // capturing the packets
    while (number_of_packets < MAX_PACKETS) {
        datasize = recvfrom(raw_sock, buf, 10000, 0, sock_addr, (socklen_t *)sizeof(sock_addr));
        if (datasize < 0) {
            fprintf(stderr, "Error while reading the packets: %s\n", strerror(errno));
            return 1;
        }
        printDetails(buf);
        number_of_packets += 1;
    }

    printf("TCP Packets: %d\n", tcp);
    printf("UDP Packets: %d\n", udp);
    printf("Number of Packets: %d\n", number_of_packets);
    return 0;
}
