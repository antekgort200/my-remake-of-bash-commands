#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PACKET_SIZE 64
#define IP_HDR_SIZE 20
#define ICMP_HDR_SIZE 8
#define MAX_HOSTNAME_LEN 256

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hostname/IP>\n", argv[0]);
        return 1;
    }

    char *target = argv[1];
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(target)) == NULL) {
        printf("err\n");
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket() error");
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt() error");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = *((struct in_addr *)host->h_addr_list[0]);

    struct icmphdr icmp_hdr;
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.code = 0;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = 0;
    icmp_hdr.checksum = 0;
    icmp_hdr.checksum = checksum(&icmp_hdr, ICMP_HDR_SIZE);

    if (sendto(sockfd, &icmp_hdr, ICMP_HDR_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        perror("sendto() error");
        return 1;
    }

    unsigned char buffer[PACKET_SIZE];
    memset(buffer, 0, sizeof(buffer));
    if (recv(sockfd, buffer, sizeof(buffer), 0) <= 0) {
        perror("recv() error");
        return 1;
    }

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct in_addr source_ip;
    source_ip.s_addr = ip_hdr->saddr;

    printf("Ping successful, source IP: %s\n", inet_ntoa(source_ip));

    close(sockfd);
    return 0;
}

