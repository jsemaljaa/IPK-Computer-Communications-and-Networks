//
// Created by jsemalja on 22/3/22.
//

// gcc main.c -lpcap -o main

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>             // memset()
#include <stdbool.h>
#include <pcap.h>
#include <time.h>

#include <arpa/inet.h>          // for inet_ntoa()
#include <netinet/ip_icmp.h>	// declarations for icmp header
#include <netinet/udp.h>	    // declarations for udp header
#include <netinet/tcp.h>	    // declarations for tcp header
#include <netinet/ip.h>	        // declarations for ip header
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#define MAX_BUFF 256
#define MAX_MAC_LEN 18
#define MAX_TIMESTAMP_LEN 30

#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

int headerLen;
pcap_t* handle;

bool tcp = false;
bool udp = false;
bool icmp = false;
bool arp = false;

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

enum errCodes{
    E_OK = 0,
    E_FINDDEVS,
    E_PCONFLICT,
    E_NOOPTARG,
    E_HANDLE
};

typedef struct parameters {
    char interface[MAX_BUFF];
    char port[10];
    int packets_number;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;
    bool printAll;
} params_t ;

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
    p.printAll = false;

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

    /* Obtaining a list of available devices in case
     * the interface was not specified by user */
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

    if(pcap_lookupnet(device, &sourceIP, &netmask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        return NULL;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return NULL;
    }

    /* Compiling a filter for packets listening */
    if(pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    /* Installing a filter */
    if(pcap_setfilter(handle, &bpf) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

void print_packet(char *timestamp, char *srcMAC, int srcP, char *srcIP, char *dstMAC, int dstP, char *dstIP, int len){
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

char *timestamp_ctor(struct timeval ts_time){
    time_t rawtime;
    time(&rawtime);
    struct tm *info = localtime(&rawtime);
    static char buffer[MAX_TIMESTAMP_LEN];
    size_t len = strftime(buffer, sizeof(buffer) - 1, "%FT%T%z", info);

    gettimeofday(&ts_time, NULL);

    int ms = ts_time.tv_usec/1000;
    char ms_char[4];
    sprintf(ms_char, "%d", ms);

    if (len > 1) {
        char minutes[] = {buffer[len-2], buffer[len-1], '\0'};
        sprintf(buffer + len - 2, ":%s", minutes);
        char timezone[] = {buffer[len-5], buffer[len-4], buffer[len-3], buffer[len-2], buffer[len-1], buffer[len], '\0'};
        sprintf(buffer + len - 5, ".%s", ms_char);
        sprintf(buffer + len - 1, "%s", timezone);
    }

    return buffer;
}

void got_packet(u_char *args, struct pcap_pkthdr *header, u_char *packet){

    struct ether_arp *arphdr;

    char *timestamp;
    timestamp = timestamp_ctor(header->ts);

    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;

    // struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    char sourceIP[MAX_BUFF] = "", destinationIP[MAX_BUFF] = "";
    char sourceMAC[MAX_MAC_LEN] = "", destinationMAC[MAX_MAC_LEN] = "";
    int sourcePort = 0, destinationPort = 0;

    // Protocols:
    // 1 for ICMP
    // 6 for TCP
    // 17 for UDP
    
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
    struct ether_header *etherhdr = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(etherhdr->ether_type);

    int ipvhdrLen, protocol;

    const int ethhdrSize = sizeof(struct ether_header);

    switch(ether_type){
        case ETHERTYPE_ARP:
            // ARP has 42 bytes in total, the first 14 bytes is Ethernet frame header
            arphdr = (struct ether_arp *)(packet + 14);
            sprintf(sourceIP, "%u:%u:%u:%u", arphdr->arp_spa[0], arphdr->arp_spa[1], arphdr->arp_spa[2], arphdr->arp_spa[3]);
            sprintf(destinationIP, "%u:%u:%u:%u", arphdr->arp_tpa[0], arphdr->arp_tpa[1], arphdr->arp_tpa[2], arphdr->arp_tpa[3]);
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
            inet_ntop(AF_INET6, &ip6hdr->ip6_src, sourceIP, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6hdr->ip6_dst, destinationIP, INET6_ADDRSTRLEN);
            // protocol?
            break;
    }

    sprintf(sourceMAC, MACSTR, etherhdr->ether_shost[0], etherhdr->ether_shost[1], etherhdr->ether_shost[2], etherhdr->ether_shost[3], etherhdr->ether_shost[4], etherhdr->ether_shost[5]);
    sprintf(destinationMAC, MACSTR, etherhdr->ether_dhost[0], etherhdr->ether_dhost[1], etherhdr->ether_dhost[2], etherhdr->ether_dhost[3], etherhdr->ether_dhost[4], etherhdr->ether_dhost[5]);

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
        default:
            break;
    }
    print_packet(timestamp, sourceMAC, sourcePort, sourceIP, destinationMAC, destinationPort, destinationIP, header->len);
}

void signal_handler(int signalNo){
    pcap_close(handle);
    exit(signalNo);
}

char *filter_ctor(params_t p){
    static char filter[MAX_BUFF];

    if (p.tcp) strcpy(filter, "tcp ");
    else if (p.udp) strcpy(filter, "udp ");

    if(p.printAll) *filter = 0;

    if(strcmp(p.port, "NONE")){
        strcat(filter, p.port);
    }
    return filter;
}

int main(int argc, char *argv[]){

    params_t p = parameters_parsing(argc, argv);

    // /* Debugging */ printf("parameters: %s %s %d %d %d %d %d\n", p.interface, p.port, p.packets_number, p.tcp, p.udp, p.arp, p.icmp);

    char *filter = filter_ctor(p);

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
