#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define ETH_ALEN 6
#define ETH_HLEN 14
#define IPV4_HL_MIN 20
#define IPV4_ALEN 4
#define TCP_PAYLOAD_MAXLEN 16

struct ethhdr
{
        u_int8_t dst_host[ETHER_ADDR_LEN];
        u_int8_t src_host[ETHER_ADDR_LEN];
        u_int16_t eth_type;
};

struct iphdr
{
        u_int8_t IHL;
        u_int8_t TOS;
        u_int16_t len;
        u_int16_t ID;
        u_int16_t flag;
        u_int8_t TTL;
        u_int8_t protocol;
        u_int16_t checkSum;
        u_int8_t src_address[4];
        u_int8_t dst_address[4];
};

struct tcphdr
{
        u_int16_t src_port;
        u_int16_t dst_port;
        u_int32_t seq_num;
        u_int32_t ack_num;
        u_int16_t frag;
        u_int16_t win_size;
        u_int16_t checkSum;
        u_int16_t urg_p;
};

void eth_print(u_int8_t *buf, int size)
{
        struct ethhdr *eth = (struct ethhdr*)(buf);

        printf("source MAC= ");
        for(int i=0; i<6; i++)
                printf("%2x ", eth->src_host[i]);

        printf("destination MAC= ");
        for(int i=0; i<6; i++)
                printf("%2x ", eth->dst_host[i]);

        int type = ntohs(ethhdr->eth_type);
        if(type!=0x0800)
                break;
        else
                ip_print(buf, size);
}

void ip_print(u_int8_t *buf, int size)
{
        struct iphdr *ip  = (struct iphdr*)(buf + sizeof(struct ethhdr));

        printf("\nsource IP: ");
        for(int i=0; i<IPV4_ALEN; i++)
                printf("%d%s", (i==IPV4_ALEN ? "" : "."), iphdr->src_address[i]);

        printf("\ndestination IP: ");
        for(int i=0; i<IPV4_ALEN; i++)
                printf("%d%s", (i==IPV4_ALEN ? "" : "."), iphdr->dst_address[i]);

        if(iphdr->protocol!=0x06)
                break;
        else
                tcp_print(buf, size);
}

void tcp_print(u_int8_t *buf, int size)
{
        struct iphdr* ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        u_int16_t ip_hdr_len = iphdr->IHL*4;
        struct tcphdr* tcp = (struct tcphdr*)(buf + ip_hdr_len + sizeof(struct ethhdr));
        u_int8_t data_offset =(uint8_t*)(tcp->frag)[0] & 0xF0;
        int header_size = sizeof(struct ethhdr) + ip_hdr_len + 4*data_offset;

        printf("source port : %2x\n", ntohs(tcp -> src_port));
        printf("destination port : %2x\n" , ntohs(tcp -> dst_port));

        printf("payload:\n");
        u_int32_t s = size - header_size < 32 ? s : 32;

        for(int i=0; i<s; i++)
                printf("%02x ", &(buf+header_size));
}

void usage() {
        printf("syntax: pcap_test <interface>\n");
        printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) 
{
        if (argc != 2) 
        {
                usage();
                return -1;
        }
        
        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) 
        {
                fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
                return -1;
        }

        while (1) 
        {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;
                printf("%u bytes captured\n", header->caplen);
                eth_print(packet, header->caplen);
        }
        pcap_close(handle);
        return 0;
}
