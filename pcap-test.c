#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define ETHER_ADDR_LEN 6

struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4; // IPv4
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char iph_flag:3;
    unsigned short int iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    int iph_sourceip;
    int iph_destip;
};

struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int tcph_seqnum;
    unsigned int tcph_acknum;
    unsigned char tcph_reserved:4, tcph_offset:4;
    unsigned char tcph_flags;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(uint8_t *m){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

char* my_inet_ntoa(int ina) {
    static char buf[16];
    sprintf(buf, "%d.%d.%d.%d",
            (ina & 0xff),
            (ina >> 8 & 0xff),
            (ina >> 16 & 0xff),
            (ina >> 24 & 0xff));
    return buf;
}
    int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr =(struct libnet_ethernet_hdr *)packet;
        printf("==========Ethernet Header==========\n");
        printf("Src MAC: ");
        print_mac(eth_hdr->ether_shost);
        printf("\nDst MAC: ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        if((eth_hdr->ether_type >> 8) | (eth_hdr->ether_type << 8) != 0x0800){
            continue;
        }

        struct ipheader* iph = (struct ipheader*)(packet + sizeof(struct libnet_ethernet_hdr));

        printf("==========IP Header==========\n");
        printf("Src IP: %s\n",my_inet_ntoa(iph->iph_sourceip));
        printf("Dst IP: %s\n",my_inet_ntoa(iph->iph_destip));

        if (iph->iph_protocol != 6) { // TCP protocol number is 6
            continue;
        }

        unsigned short iphdrlen = iph->iph_ihl*4;
        struct tcpheader* tcph = (struct tcpheader*)(packet + iphdrlen + sizeof(struct libnet_ethernet_hdr));

        printf("==========TCP Header==========\n");
        printf("Src Port: %u\n", (tcph->tcph_srcport >> 8) | (tcph->tcph_srcport << 8));
        printf("Dst Port: %u\n", (tcph->tcph_destport >> 8) | (tcph->tcph_destport << 8));

        unsigned short tcpdrlen = tcph->tcph_offset*4;
        int payload_len = ((iph->iph_len >> 8) | (iph->iph_len << 8)) - iphdrlen - tcpdrlen;
        const u_char* payload = (u_char*)(packet + iphdrlen + tcpdrlen + sizeof(struct libnet_ethernet_hdr));
        printf("==========Data==========\n");
        for(int i = 0; i < payload_len && i < 10; i++) {
            printf("%02x ", *(payload + i));
        }
        printf("\n");

    }

    pcap_close(pcap);
}
