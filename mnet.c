#define APP_NAME    "sniffex"
#define APP_DESC    "Sniffer example using libpcap"
#define APP_COPYRIGHT    "Copyright (c) 2005"
#define APP_DISCLAIMER    "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_BSD
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <netdb.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


#define iscrlf(p) (*p == '\r' && *(p + 1) == '\n')
#define notcrlf(p) (*p != '\r' && *(p + 1) != '\n')

#define notend(p) (*p != '\0')
#define end(p) (*p == '\0')

//#define IP_HL(ip) (((ip)->ip_hl) & 0x0f)
//#define IP_V(ip) (((ip)->ip_hl) >> 4)
//#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN    6

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int
libnet_send(struct ether_header *ether, struct ip *iphdr, struct tcphdr *tcphdr, int size_payload, const u_char *payload);

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1; /* packet counter */    
    /* declare pointers to packet headers */
    //const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
    //const struct sniff_ip *ip; /* The IP header */
    //const struct sniff_tcp *tcp; /* The TCP header */

    struct ether_header *ether = NULL;    
    struct ip *iphdr = NULL;
    struct tcphdr *tcphdr = NULL;
    struct pcap_pkthdr pkthdr;

    int size_ip = 20;
    int size_tcp;
    int size_payload;    
    const u_char *payload; /* Packet payload */

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ether = (struct ether_header *)(packet);
    iphdr = (struct ip *)(packet + 14);
    tcphdr = (struct tcphdr *)(packet + 14 + 20);

    size_tcp = tcphdr->th_off * 4;    
    size_payload = ntohs(iphdr->ip_len) - (size_ip + size_tcp);

    printf("-----------------------------------------\n");
    printf("ACK: %u\n", ntohl(tcphdr->th_ack));
    printf("SEQ: %u\n", ntohl(tcphdr->th_seq));
    printf("DST IP: %s:%d\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
    printf("SRC IP: %s:%d\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
    printf(" ip_ttl: %d\n", iphdr->ip_ttl);
    printf(" ip_id:  %d|OK:%d|OK:%d\n", iphdr->ip_id, htons(iphdr->ip_id), ntohs(iphdr->ip_id));
    printf(" ip_off: %d|%d|%d\n", iphdr->ip_off, htons(iphdr->ip_off), ntohs(iphdr->ip_off));
    printf(" ip_len: %d|OK:%d|OK:%d\n", iphdr->ip_len, htons(iphdr->ip_len), ntohs(iphdr->ip_len));
    printf(" ip_tos: %d|%d|%d\n", iphdr->ip_tos, htons(iphdr->ip_tos), ntohs(iphdr->ip_tos));
    printf(" th_win: %d|OK: %d|OK: %d\n", tcphdr->th_win, htons(tcphdr->th_win), ntohs(tcphdr->th_win));
    printf(" th_sum: %d|%d|%d\n", tcphdr->th_sum, htons(tcphdr->th_sum), ntohs(tcphdr->th_sum));
    printf(" th_off: %d|%d|%d\n", tcphdr->th_off, htons(tcphdr->th_off), ntohs(tcphdr->th_off));
    printf("size_payload: %d\n", size_payload);
    printf("-----------------------------------------\n");

    //size_tcp = TH_OFF(tcphdr)*4;

    if (size_tcp < 20) {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    /* compute tcp payload (segment) size */
    size_payload = ntohs(iphdr->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf(" Payload (%d bytes):\n", size_payload);
        printf("%s", payload);
        if (ntohs(tcphdr->th_dport) == 80)
        {
            libnet_send(ether, iphdr, tcphdr, size_payload, payload);
        }
    }

    return;
}


int
libnet_send(struct ether_header *ether, struct ip *iphdr, struct tcphdr *tcphdr, int size_payload, const u_char *payload)
{
    char *dev = "eth0";
    libnet_t *handle; /* Libnet句柄 */
    int packet_size; /* 构造的数据包大小 */

    char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    libnet_ptag_t eth_tag, ip_tag, tcp_tag, tcp_op_tag; /* 各层build函数返回值 */
    u_short proto = IPPROTO_TCP; /* 传输层协议 */
    u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */    

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, inet_ntoa(iphdr->ip_dst), LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, inet_ntoa(iphdr->ip_src), LIBNET_RESOLVE);

    /* 初始化Libnet */
    if ( (handle = libnet_init(LIBNET_LINK, dev, error)) == NULL ) {
        printf("libnet_init failure\n");
        return (-1);
    };
    //strncpy(payload, "test", sizeof(payload)-1); /* 构造负载的内容 */
    //payload_s = strlen(payload); /* 计算负载内容的长度 */

#if 0
    /* 构建TCP的选项,通常在第一个TCP通信报文中设置MSS */
    tcp_op_tag = libnet_build_tcp_options(
                payload,
                size_payload,
                handle,
                0
    );
    if (tcp_op_tag == -1) {
        printf("build_tcp_options failure\n");
        return (-2);
    };
#endif
    tcp_tag = libnet_build_tcp(
                ntohs(tcphdr->th_sport),  /* 源端口 */
                ntohs(tcphdr->th_dport),  /* 目的端口 */
                ntohl(tcphdr->th_seq),    /* 序列号 */
                ntohl(tcphdr->th_ack),    /* 确认号 */
                TH_PUSH | TH_ACK,         /* Control flags */
                htons(tcphdr->th_win),    /* 窗口尺寸 */
                0,                        /* 校验和,0为自动计算 */
                0,                        /* 紧急指针 */
                LIBNET_TCP_H + size_payload, /* 长度 */
                payload,                  /* 负载内容 */
                size_payload,             /* 负载内容长度 */
                handle,                   /* libnet句柄 */
                0                         /* 新建包 */
    );
    if (tcp_tag == -1) {
        printf("libnet_build_tcp failure\n");
        return (-3);
    };
    /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + size_payload, /* IP协议块的总长,*/
        0, /* tos */
        ntohs(iphdr->ip_id), //(u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
        IP_DF, /* frag 片偏移 */
        iphdr->ip_ttl, //(u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
        proto, /* 上层协议 */
        0, /* 校验和，此时为0，表示由Libnet自动计算 */
        src_ip, /* 源IP地址,网络序 */
        dst_ip, /* 目标IP地址,网络序 */
        NULL, /* 负载内容或为NULL */
        0, /* 负载内容的大小*/
        handle, /* Libnet句柄 */
        0 /* 协议块标记可修改或创建,0表示构造一个新的*/
    );
    if (ip_tag == -1) {
        printf("libnet_build_ipv4 failure\n");
        return (-4);
    };
    /* 构造一个以太网协议块,只能用于LIBNET_LINK */
    eth_tag = libnet_build_ethernet(
        ether->ether_dhost, /* 以太网目的地址 */
        ether->ether_shost, /* 以太网源地址 */
        ETHERTYPE_IP, /* 以太网上层协议类型，此时为IP类型 */
        NULL, /* 负载，这里为空 */ 
        0, /* 负载大小 */
        handle, /* Libnet句柄 */
        0 /* 协议块标记，0表示构造一个新的 */ 
    );
    if (eth_tag == -1) {
        printf("libnet_build_ethernet failure\n");
        return (-5);
    };

    packet_size = libnet_write(handle); /* 发送已经构造的数据包*/
    libnet_destroy(handle); /* 释放句柄 */
    printf("send packet complete.");
    return (0);
}    



int main(int argc, char **argv)
{
    char *dev = NULL;        /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];    /* error buffer */
    pcap_t *handle;        /* packet capture handle */

    //char filter_exp[] = "dst 202.114.85.31 and tcp";   
    char filter_exp[] = "host 192.168.1.103 and tcp";    /* filter expression [3] */
    struct bpf_program fp;        /* compiled filter program (expression) */
    bpf_u_int32 mask;        /* subnet mask */
    bpf_u_int32 net;        /* ip */
    int num_packets = 10;        /* number of packets to capture */

    //print_app_banner();

    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        //print_app_usage();
        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}
