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
#include <signal.h>             // signal()
#include <time.h>

#include <arpa/inet.h>          // for inet_ntoa()
#include <netinet/ip_icmp.h>	// declarations for icmp header
#include <netinet/udp.h>	    // declarations for udp header
#include <netinet/tcp.h>	    // declarations for tcp header
#include <netinet/ip.h>	        // declarations for ip header
#include <netinet/ip6.h>

#define IPv4_T 2048
#define IPv6_T 34525
#define MAX_BUFF 256
#define MAX_TIMESTAMP_LEN 30

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

    int packetsCount = p.tcp + p.udp + p.icmp;

    if(packetsCount >= 2){
        fprintf(stderr, "%s", errCodesMsg[E_PCONFLICT]);
        exit(E_PCONFLICT);
    }

    bool allPackets = p.tcp && p.udp && p.icmp && p.arp;
    bool nonePackets = !p.tcp && !p.udp && !p.icmp && !p.arp;

    if(allPackets || nonePackets){
        p.printAll = true;
    } else {
        tcp = p.tcp;
        udp = p.udp;
        icmp = p.icmp;
        arp = p.arp;
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

    if(pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    if(pcap_setfilter(handle, &bpf) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

void get_header_len_by_link(pcap_t* handle){
    int link_type;

    if((link_type = pcap_datalink(handle)) < 0){
        fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(handle));
        return;
    }

    switch (link_type) {
        case DLT_NULL:
            headerLen = 4;
            break;
        case DLT_EN10MB:
            headerLen = 14;
            break;
        case DLT_SLIP:
        case DLT_PPP:
            headerLen = 24;
            break;
        default:
            fprintf(stderr, "error datalink (%d)\n", link_type);
            headerLen = 0;
            return;
    }
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

void display_base(const char *timestamp, char *srcIP, char *dstIP, struct ip* iphdr){
    printf("timestamp: %s\n", timestamp);
    printf("src MAC: \n");
    printf("dst MAC: \n");
    printf("frame length: %d bytes\n", ntohs(iphdr->ip_len));
    printf("src IP: %s\n", srcIP);
    printf("dst IP: %s\n", dstIP);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
    bool IPv6F = false, IPv4F = false;
    int IPv6offset = 0;

    char *timestamp = timestamp_ctor(header->ts);

    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;

    struct icmp* icmphdr;

    struct tcphdr* tcphdr;

    struct udphdr* udphdr;
    char iphdrInfo[MAX_BUFF];

    char sourceIP[MAX_BUFF];
    char destinationIP[MAX_BUFF];

    int packets = 1;

    buffer += headerLen;

    iphdr = (struct ip*) buffer;

    strcpy(sourceIP, inet_ntoa(iphdr->ip_src));
    strcpy(destinationIP, inet_ntoa(iphdr->ip_dst));

    // from the start to header->caplen

    // Protocols:
    // 1 for ICMP
    // 6 for TCP
    // 17 for UDP
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
           ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
           4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    buffer += 4*iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            if(tcp){
                display_base(timestamp, sourceIP, destinationIP, iphdr);
                tcphdr = (struct tcphdr*)buffer;
                printf("TCP ");
                printf("%s\n", iphdrInfo);
                printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                       (tcphdr->th_flags & TH_URG ? 'U' : '*'),
                       (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
                       (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
                       (tcphdr->th_flags & TH_RST ? 'R' : '*'),
                       (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
                       (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
                       ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
                       ntohs(tcphdr->th_win), 4*tcphdr->th_off);
                printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
                packets += 1;
            }
            break;

        case IPPROTO_UDP:
            if(udp){
                display_base(timestamp, sourceIP, destinationIP, iphdr);
                udphdr = (struct udphdr*)buffer;
                printf("UDP  %s:%d -> %s:%d\n", sourceIP, ntohs(udphdr->uh_sport),
                       destinationIP, ntohs(udphdr->uh_dport));
                printf("%s\n", iphdrInfo);
                printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
                packets += 1;
            }
            break;

        case IPPROTO_ICMP:
            if(icmp){
                display_base(timestamp, sourceIP, destinationIP, iphdr);
                icmphdr = (struct icmp*)buffer;
                printf("ICMP %s -> %s\n", sourceIP, destinationIP);
                printf("%s\n", iphdrInfo);
                printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
                       ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
                printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
                packets += 1;
            }
            break;
    }
}

void signal_handler(int signalNo){
    struct pcap_stat stats;

    if(pcap_stats(handle, &stats) >= 0){
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }

    pcap_close(handle);
    exit(0);
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

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    handle = handling_pcap(p.interface, filter);
    if(handle == NULL){
        exit(-1);
    }

    get_header_len_by_link(handle);
    if(headerLen == 0){
        exit(-1);
    }

    if (pcap_loop(handle, p.packets_number, got_packet, (u_char*)NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    signal_handler(0);

    return 0;
}
