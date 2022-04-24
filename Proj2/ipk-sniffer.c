/*
 *  Computer Communications and Networks University Course
 *  Project 2 - Packet Sniffer
 *  Author: Alina Vinogradova (xvinog00)
 *  Email: xvinog00@stud.fit.vubr.cz
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>

#include <pcap.h>
#include <arpa/inet.h>          // inet_ntoa(), ntohs()
#include <netinet/udp.h>	    // declarations for udp header
#include <netinet/tcp.h>	    // declarations for tcp header
#include <netinet/ip.h>	        // declarations for ip header
#include <netinet/ip6.h>        // declarations for ip6 header
#include <netinet/if_ether.h>   // declarations for ethernet header

#define MAX_BUFF 256
#define MAX_MAC_LEN 18
#define MAX_TIMESTAMP_LEN 30

#define PROTOCOL_ICMP_IPv4 1
#define PROTOCOL_ICMP_IPv6 58
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define IPSTR "%u:%u:%u:%u"

const char *helpMessage =
        "Packets sniffer in C using pcap.h\n"
        "Usage:\n"
        "       ./ipk-sniffer [-i interface_name | --interface interface_name] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
        "Where:\n"
        "[-i interface_name | --interface interface_name] is just one interface on which to listen.\n"
        "                                                 If this parameter is not specified, or if only -i is specified without a value,\n"
        "                                                 the list of active interfaces is printed.\n"
        " ----------------------------------------------------------------------------------------------------------------------------------------------\n"
        "{-p port}                                        will filter packets on a given interface by port;\n "
        "                                                if this parameter is not specified, all ports are considered;\n"
        "                                                 if the parameter is specified, the port can occur in both the source and destination part.\n"
        " ----------------------------------------------------------------------------------------------------------------------------------------------\n"
        "[-t | --tcp]                                     will display only TCP packets.\n"
        " ----------------------------------------------------------------------------------------------------------------------------------------------\n"
        "[-u | --udp]                                     will display only UDP packets.\n"
        " ----------------------------------------------------------------------------------------------------------------------------------------------\n"
        "[--icmp]                                         will display only ICMPv6 and ICMPv4 packets.\n"
        "\n"
        "Unless specific protocols are specified, all protocols are considered for printing\n"
        " ----------------------------------------------------------------------------------------------------------------------------------------------\n"
        "[-n num]                                         specifies the number of packets to be displayed.\n"
        "                                                 If not specified, consider displaying only one packet, as if -n 1\n";

typedef struct parameters {
    char interface[MAX_BUFF];
    char port[10];
    unsigned int packets_number;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;
    bool printAll;
} params_t ;

enum errCodes{
    E_OK = 0,
    E_FINDDEVS,
    E_PCONFLICT,
    E_NOOPTARG
};

const char *errCodesMsg[] = {
        [E_OK] = "No errors\n",
        [E_FINDDEVS] = "Error finding devices\n",
        [E_PCONFLICT] = "Packets selection conflict\n",
        [E_NOOPTARG] = "Required parameter is missing. Type ./ipk-sniffer -h to get help\n"
};

params_t parameters_parsing(int argc, char *argv[]){
    params_t p;

    // Parameters initialization

    *p.interface = 0;
    p.packets_number = 0;
    strcpy(p.port, "NONE");
    p.tcp = false;
    p.udp = false;
    p.arp = false;
    p.icmp = false;

    // Parsing long parameters (starting with "--")

    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--tcp")){
            p.tcp = true;
            argv[i] = "";
        } else if (!strcmp(argv[i], "--udp")){
            p.udp = true;
            argv[i] = "";
        } else if (!strcmp(argv[i], "--arp")){
            p.arp = true;
            argv[i] = "";
        } else if (!strcmp(argv[i], "--icmp")){
            p.icmp = true;
            argv[i] = "";
        } else if (!strcmp(argv[i], "--interface")) {
            if(argv[i + 1] != NULL && (strncmp(argv[i + 1], "-", 1) != 0)){
                strcpy(p.interface, argv[i + 1]);
                argv[i] = "";
                argv[i+1] = "";
            }
        }
    }

    // Parsing short parameters

    int c;
    while((c = getopt(argc, argv, ":i:p:tun:h")) != -1){
        switch (c) {
            case 'i':
                if(!strncmp(optarg, "-", 1) || optarg == NULL){
                    break;
                } else {
                    strcpy(p.interface, optarg);
                }
                break;
            case 'p':
                if(optarg != NULL && (strncmp(optarg, "-", 1) != 0)) {
                    strcpy(p.port, "port ");
                    strcat(p.port, optarg);
                } else {
                    fprintf(stderr, "%s", errCodesMsg[E_NOOPTARG]);
                    exit(E_NOOPTARG);
                }
                break;
            case 't':
                p.tcp = true;
                break;
            case 'u':
                p.udp = true;
                break;
            case 'n':
                p.packets_number = atoi(optarg);
                break;
            case 'h':
                printf("%s", helpMessage);
                exit(0);
                break;
        }
    }

    bool allPackets = p.tcp && p.udp && p.icmp && p.arp;

    if(allPackets){
        p.tcp = false;
        p.udp = false;
        p.icmp = false;
        p.arp = false;
    }

    int packetsCount = p.tcp + p.udp + p.icmp;

    if(packetsCount >= 2){
        fprintf(stderr, "%s", errCodesMsg[E_PCONFLICT]);
        exit(E_PCONFLICT);
    }

    if(p.packets_number == 0) p.packets_number = 1;
    return p;
}

pcap_t* handling_pcap(char* device, const char* filter){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t *devices = NULL, *dev = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask, sourceIP;

    /*
        Obtaining a list of available devices in case
        the interface was not specified by user
    */
    if(!strcmp(device, "")){
        if(pcap_findalldevs(&devices, errbuf) == -1){
            fprintf(stderr, "%s", errCodesMsg[E_FINDDEVS]);
            return NULL;
        }

        for (dev = devices; dev != NULL; dev = dev->next) {
            printf("%s\n", dev->name);
        }
        pcap_freealldevs(devices);
        exit(0);
    }

    /* Opening the device for data capturing */
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return NULL;
    }

    /* Obtaining netmask for filter, sourceip */
    if(pcap_lookupnet(device, &sourceIP, &netmask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        return NULL;
    }

    /* Compiling a filter for packets listening */
    if(pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == PCAP_ERROR){
        fprintf(stderr, "Couldn't compile filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    /* Installing a filter */
    if(pcap_setfilter(handle, &bpf) == PCAP_ERROR){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

void display_packet_data(char *timestamp, char *srcMAC, int srcP, char *srcIP, char *dstMAC, int dstP, char *dstIP, int len){
    printf("timestamp: %s\n", timestamp);
    printf("src MAC: %s\n", srcMAC);
    printf("dst MAC: %s\n", dstMAC);
    printf("frame length: %d bytes\n", len);
    printf("src IP: %s\n", srcIP);
    printf("dst IP: %s\n", dstIP);
    printf("src port: %d\n", srcP);
    printf("dst port: %d\n", dstP);
    printf("\n");
}

void display_packet_dump(const u_char* packet, const int len){

    // 16 values per one line
    // Buffer has to be the size of 16 + 1 for '\0'
    unsigned char buff[17];

    int i;
    for (i = 0; i < len; ++i) {
        if((i % 16) == 0){
            if(i != 0) printf("  %s\n", buff);
            printf("0x%04X:", i);
        }
        printf(" %02x", packet[i]);
        if(i % 16 == 7) printf(" ");
        isprint(packet[i]) ? (buff[i % 16] = packet[i]) : (buff[i % 16] = '.');
        buff[(i % 16) + 1] = '\0';
    }

    while((i % 16) != 0){
        printf("   ");
        i++;
    }

    printf("  %s\n", buff);
}

char *timestamp_ctor(struct timeval ts_time){
    time_t rawtime;
    time(&rawtime);
    struct tm *info = localtime(&rawtime);
    static char buffer[MAX_TIMESTAMP_LEN];
    size_t l = strftime(buffer, sizeof(buffer) - 1, "%FT%T%z", info);

    gettimeofday(&ts_time, NULL);

    int ms = ts_time.tv_usec/1000;
    char ms_char[4];
    sprintf(ms_char, "%d", ms);

    if (l > 1) {
        char minutes[] = {buffer[l-2], buffer[l-1], '\0'};
        sprintf(buffer + l - 2, ":%s", minutes);
        char timezone[] = {buffer[l-5], buffer[l-4], buffer[l-3], buffer[l-2], buffer[l-1], buffer[l], '\0'};
        sprintf(buffer + l - 5, ".%s", ms_char);
        sprintf(buffer + l - 1, "%s", timezone);
    }

    return buffer;
}

void got_packet(u_char *args, struct pcap_pkthdr *header, u_char *packet){

    struct ether_arp *arphdr;

    char *timestamp;
    timestamp = timestamp_ctor(header->ts);

    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;

    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    char sourceIP[MAX_BUFF] = "", destinationIP[MAX_BUFF] = "";
    char sourceMAC[MAX_MAC_LEN] = "", destinationMAC[MAX_MAC_LEN] = "";
    int sourcePort = 0, destinationPort = 0;

    struct ether_header *etherhdr = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(etherhdr->ether_type);

    sprintf(sourceMAC, MACSTR, etherhdr->ether_shost[0], etherhdr->ether_shost[1], etherhdr->ether_shost[2], etherhdr->ether_shost[3], etherhdr->ether_shost[4], etherhdr->ether_shost[5]);
    sprintf(destinationMAC, MACSTR, etherhdr->ether_dhost[0], etherhdr->ether_dhost[1], etherhdr->ether_dhost[2], etherhdr->ether_dhost[3], etherhdr->ether_dhost[4], etherhdr->ether_dhost[5]);

    int ipvhdrLen, protocol;

    const int ethhdrSize = sizeof(struct ether_header);

    switch(ether_type){
        case ETHERTYPE_ARP:
            // ARP has 42 bytes in total, the first 14 bytes is Ethernet frame header
            arphdr = (struct ether_arp *)(packet + 14);
            sprintf(sourceIP, IPSTR, arphdr->arp_spa[0], arphdr->arp_spa[1], arphdr->arp_spa[2], arphdr->arp_spa[3]);
            sprintf(destinationIP, IPSTR, arphdr->arp_tpa[0], arphdr->arp_tpa[1], arphdr->arp_tpa[2], arphdr->arp_tpa[3]);
            break;
        case ETHERTYPE_IP:
            iphdr = (struct ip *)(packet + ethhdrSize);
            // IPv4 doesn't have a fixed header length, minimum 20 bytes and maximum 60 bytes
            ipvhdrLen = iphdr->ip_hl * 4;
            protocol = iphdr->ip_p;
            strcpy(sourceIP, inet_ntoa(iphdr->ip_src));
            strcpy(destinationIP, inet_ntoa(iphdr->ip_dst));
            break;
        case ETHERTYPE_IPV6:
            ip6hdr = (struct ip6_hdr *)(packet + ethhdrSize);
            // IPv6 has 40 bytes as fixed header length
            ipvhdrLen = 40;
            protocol = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            inet_ntop(AF_INET6, &ip6hdr->ip6_src, sourceIP, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6hdr->ip6_dst, destinationIP, INET6_ADDRSTRLEN);
            break;
    }

    switch(protocol){
        case PROTOCOL_TCP:
            tcphdr = (struct tcphdr*)(packet + ethhdrSize + ipvhdrLen);
            sourcePort = ntohs(tcphdr->th_sport);
            destinationPort = ntohs(tcphdr->th_dport);
            break;
        case PROTOCOL_UDP:
            udphdr = (struct udphdr*)(packet + ethhdrSize + ipvhdrLen);
            sourcePort = ntohs(udphdr->uh_sport);
            destinationPort = ntohs(udphdr->uh_dport);
            break;
        case PROTOCOL_ICMP_IPv4:
        case PROTOCOL_ICMP_IPv6:
            break;
        default:
            fprintf(stderr, "Unknown protocol %d. Type ./ipk-sniffer -h for help\n", protocol);
            break;
    }
    display_packet_data(timestamp, sourceMAC, sourcePort, sourceIP, destinationMAC, destinationPort, destinationIP, header->len);
    display_packet_dump(packet, header->len);
}

char *filter_ctor(params_t p){
    static char filter[MAX_BUFF];

    if(p.arp){
        if (p.tcp) strcpy(filter, "arp or tcp ");
        else if (p.udp) strcpy(filter, "arp or udp ");
        else if (p.icmp) strcpy(filter, "arp or icmp or icmp6 ");
        else strcpy(filter, "arp ");
    } else {
        if (p.tcp) strcpy(filter, "tcp ");
        else if (p.udp) strcpy(filter, "udp ");
        else if (p.icmp) strcpy(filter, "icmp or icmp6 ");
    }

    if(strcmp(p.port, "NONE")){
        if(!strcmp(filter, "")) strcpy(filter, p.port);
        else {
            strcat(filter, "or ");
            strcat(filter, p.port);
        }
    }

    return filter;
}

int main(int argc, char *argv[]){

    params_t p = parameters_parsing(argc, argv);

    char *filter = filter_ctor(p);

    pcap_t* handle;
    handle = handling_pcap(p.interface, filter);
    if(handle == NULL){
        exit(-1);
    }

    if (pcap_loop(handle, p.packets_number, (pcap_handler)got_packet, (u_char*)NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;
}