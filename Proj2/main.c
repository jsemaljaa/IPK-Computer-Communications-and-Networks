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


#include <arpa/inet.h>          // for inet_ntoa()
#include <netinet/ip_icmp.h>	// declarations for icmp header
#include <netinet/udp.h>	    // declarations for udp header
#include <netinet/tcp.h>	    // declarations for tcp header
#include <netinet/ip.h>	        // declarations for ip header

#define IPv4_T 2048
#define IPv6_T 34525

int header;

const char *helpMessage =
        "Packets sniffer in C using pcap.h\n"
        "Usage:\n"
        "       ./ipk-sniffer [-i interface_name | --interface interface_name] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
        "Where:\n"
        "       [-i interface_name | --interface interface_name]\n "
        "       is just one interface on which to listen.\n"
        "       If this parameter is not specified, or if only -i is specified without a value,\n "
        "       the list of active interfaces is printed.\n"
        "\n"
        "       {-p port}\n "
        "       will filter packets on a given interface by port;\n "
        "       if this parameter is not specified, all ports are considered;\n"
        "       if the parameter is specified, the port can occur in both the source and destination part.\n"
        "\n"
        "       [-t | --tcp]\n"
        "       will display only TCP packets.\n"
        "       [-u | --udp]";

enum errCodes{
    E_OK = 0,
    E_FINDDEVS,
    E_PCONFLICT,
    E_NOOPTARG
};

typedef struct parameters {
    char interface[256];
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
    }

    return p;
}

pcap_t* handling_pcap(char* device, const char* filter){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t *devices = NULL, *dev = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask, sourceip;

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
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return NULL;
    }

    if(pcap_lookupnet(device, &sourceip, &netmask, errbuf) == PCAP_ERROR){
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    if(pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == PCAP_ERROR){
        fprintf(stderr, "pcap_compile: %s\n", errbuf);
        return NULL;
    }

    if(pcap_setfilter(handle, &bpf) == PCAP_ERROR){
        fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
        return NULL;
    }

    return handle;
}

void get_link_header_len(pcap_t* handle){
    int linktype;

    if((linktype = pcap_datalink(handle)) == PCAP_ERROR){
        fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(handle));
        return;
    }

    switch (linktype) {
        case DLT_NULL:
            header = 4;
            break;
        case DLT_EN10MB:
            header = 14;
            break;
        case DLT_SLIP:
        case DLT_PPP:
            header = 24;
            break;
        default:
            fprintf(stderr, "error datalink (%d)\n", linktype);
            header = 0;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr){
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrI[256];
    char sourceip[256];
    char destip[256];

    int packets = 10;

    packetptr += header;
    iphdr = (struct ip*) packetptr;
    strcpy(sourceip, inet_ntoa(iphdr->ip_src));
    strcpy(destip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrI, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr*)packetptr;
            printf("TCP  %s:%d -> %s:%d\n", sourceip, ntohs(tcphdr->th_sport),
                   destip, ntohs(tcphdr->th_dport));
            printf("%s\n", iphdrI);
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
            break;

        case IPPROTO_UDP:
            udphdr = (struct udphdr*)packetptr;
            printf("UDP  %s:%d -> %s:%d\n", sourceip, ntohs(udphdr->uh_sport),
                   destip, ntohs(udphdr->uh_dport));
            printf("%s\n", iphdrI);
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break;

        case IPPROTO_ICMP:
            icmphdr = (struct icmp*)packetptr;
            printf("ICMP %s -> %s\n", sourceip, destip);
            printf("%s\n", iphdrI);
            printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
                   ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break;
    }
}

void signal_handler(int signalNo){
    struct pcap_stat stats;

//    if(pcap_stats(pd, &stats) >= 0){
//        printf("\n%d packets captured\n", packets);
//        printf("%d packets received\n", stats.ps_recv);
//        printf("%d packets dropped\n\n", stats.ps_drop);
//    }

    //pcap_close(pd);
    exit(0);
}

int main(int argc, char *argv[]){

    params_t p = parameters_parsing(argc, argv);

    // /* Debugging */ printf("parameters: %s %s %d %d %d %d %d\n", p.interface, p.port, p.packets_number, p.tcp, p.udp, p.arp, p.icmp);

    char device[256];
    char filter[256];

    *filter = 0;
    strcpy(device, p.interface);

    if (p.tcp) strcpy(filter, "tcp ");
    else if (p.udp) strcpy(filter, "udp ");

    if(p.printAll) *filter = 0;

    if(strcmp(p.port, "NONE")){
        strcat(filter, p.port);
    }

    pcap_t* handle;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    handle = handling_pcap(device, filter);
    if(handle == NULL){
        exit(-1);
    }

    get_link_header_len(handle);
    if(header == 0){
        exit(-1);
    }

    if (pcap_loop(handle, p.packets_number, packet_handler, (u_char*)NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    signal_handler(0);

    return 0;
}
