
#define APP_NAME	"sniffex"
#define APP_DESC	"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."


#include <stdbool.h>
#include <stdint.h>

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#include "include/h3.h"

#define iscrlf(p) (*p == '\r' && *(p + 1) == '\n')
#define notcrlf(p) (*p != '\r' && *(p + 1) != '\n')

#define notend(p) (*p != '\0')
#define end(p) (*p == '\0')



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl; /* version << 4 | header length >> 2 */
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
	#define IP_RF 0x8000 /* reserved fragment flag */
	#define IP_DF 0x4000 /* dont fragment flag */
	#define IP_MF 0x2000 /* more fragments flag */
	#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void 
modify_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

int
libnet_send(struct sniff_ethernet *ethernet, struct sniff_ip *ip, struct sniff_tcp *tcp, int size_payload, const u_char *payload);


/*
 * app name/banner
 */
void
print_app_banner(void)
{
	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{
	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf(" interface Listen on <interface> for packets.\n");
	printf("\n");

	return;
}

/*
 * print data in rows of 16 bytes: offset hex ascii
 * 00000 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf(" ");
		}
	}
	printf(" ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;		/* number of bytes per line */
	int line_len;
	int offset = 0;			/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	return;
}


void 
modify_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;		/* number of bytes per line */
	int line_len;
	int offset = 0;			/* zero-based offset counter */
	const u_char *ch = payload;
	const u_char get_str[2048];
	
	RequestHeader *header;
    header = h3_request_header_new();
    h3_request_header_parse(header, payload, len);
	//printf("HEADER\n");
    printf("===========================\n");
    printf("%s", payload);
    printf("\n---------------------------\n");
    printf("Method: %.*s\n", header->RequestMethodLen, header->RequestMethod);
    printf("Request-URI: %.*s\n", header->RequestURILen, header->RequestURI);
    //printf("HTTP-Version: %.*s\n", header->HTTPVersionLen, header->HTTPVersion);
	//printf("HOST: %s\n", h3_get_host(header));	
	int i;	
	for (i=0; i<header->HeaderSize; i++) {
		HeaderField * field = &header->Fields[ i ];
		//printf("name: %s\n", header->Fields[ i ].FieldName);
		u_char * filedName[215];
		u_char host[] = "Host"; 
		sprintf(filedName, "%.*s", field->FieldNameLen, field->FieldName);
		if( strcmp(filedName, host) == 0) {			
			printf("----match host: %s = %.*s\n", filedName, field->ValueLen, field->Value);
		}
		printf("==> %.*s ==> %.*s\n", field->FieldNameLen, field->FieldName, field->ValueLen, field->Value );
	}
	h3_request_header_free(header);
	printf("-> end1 modify_payload\n");
	//return header->RequestURI;
	return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1; /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf(" * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf(" From: %s\n", inet_ntoa(ip->ip_src));
	printf(" To: %s\n", inet_ntoa(ip->ip_dst));
	printf(" Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
	printf(" Dest   MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
	
	printf(" ip_ttl: %d\n", ip->ip_ttl);
	printf(" ip_id: %d\n", ip->ip_id);
	printf(" ip_off: %d\n", ip->ip_off);
	printf(" ip_len: %d\n", ip->ip_len);
	printf(" ip_tos: %d\n", ip->ip_tos);
	printf(" ip_vhl: %d\n", ip->ip_vhl);


	/* determine protocol */	
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		printf(" Protocol: TCP\n");
		break;
	case IPPROTO_UDP:
		printf(" Protocol: UDP\n");
		return;
	case IPPROTO_ICMP:
		printf(" Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf(" Protocol: IP\n");
		return;
	default:
		printf(" Protocol: unknown\n");
		return;
	}
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf(" Src port: %d\n", ntohs(tcp->th_sport));
	printf(" Dst port: %d\n", ntohs(tcp->th_dport));
	printf(" th_seq: %d | %d\n", tcp->th_seq, htonl(tcp->th_seq));
	printf(" th_ack: %d | %d\n", tcp->th_ack, htonl(tcp->th_ack));
	printf(" th_win: %d | %d\n", ntohs(tcp->th_win), htonl(tcp->th_win));
	printf(" th_offx2: %d\n", ntohs(tcp->th_offx2));
	printf(" th_sum: %d\n", ntohs(tcp->th_sum));
	printf(" th_urp: %d\n", ntohs(tcp->th_urp));
	printf(" size_tcp: %d\n", ntohs(size_tcp));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf(" Payload (%d bytes):\n", size_payload);
		if (ntohs(tcp->th_dport) == 80)
		{
			modify_payload(payload, size_payload);
			//modify_payload(payload, size_payload);			
			//printf("-> modify_payload end \n");
			//print_payload(payload, size_payload);
			
			const u_char new_payload[2048];
			const char * p = payload;
			while (notend(p) && ! isspace(*p) ) p++;

    		if ( end(p) || iscrlf(p) ) {
        		// set error
        		return NULL;
    		}
   
    		const char * RequestMethod = payload;
    		int RequestMethodlen = p - payload;
			printf("--> RequestMethod: %.*s\n", RequestMethodlen, RequestMethod);
			
			while (isspace(*p) && notcrlf(p) && notend(p) ) p++;
			const char *RequestURI = p;		
			while (!isspace(*p) && notcrlf(p) && notend(p) ) p++;
			int RequestURIlen = p - RequestURI;			
			printf("--> RequestURI: %.*s\n", RequestURIlen, RequestURI); 
			
			const char * change_uri = "/download/download.html";
			sprintf(new_payload, "%.*s %s %s", RequestMethodlen, RequestMethod, change_uri, p);
			//memcpy(new_payload, RequestMethod, RequestMethodlen);
			printf("--> new_payload: len: %d | %s\n", strlen(new_payload), new_payload);

			libnet_send(ethernet, ip, tcp, strlen(new_payload),  new_payload);
		}					
	}
	return;
}

int
libnet_send(struct sniff_ethernet *ethernet, struct sniff_ip *ip, struct sniff_tcp *tcp, int size_payload, const u_char *payload)
{	
	char *dev = "eth0";
	libnet_t *handle; /* Libnet句柄 */
	int packet_size; /* 构造的数据包大小 */
	
	char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
	libnet_ptag_t eth_tag, ip_tag, tcp_tag, tcp_op_tag; /* 各层build函数返回值 */
	u_short proto = IPPROTO_TCP; /* 传输层协议 */
	u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
	
	
	/* 把目的IP地址字符串转化成网络序 */
	dst_ip = libnet_name2addr4(handle, inet_ntoa(ip->ip_dst), LIBNET_RESOLVE);
	/* 把源IP地址字符串转化成网络序 */
	src_ip = libnet_name2addr4(handle, inet_ntoa(ip->ip_src), LIBNET_RESOLVE);
	
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
                ntohs(tcp->th_sport),                    /* 源端口 */
                ntohs(tcp->th_dport),                    /* 目的端口 */
                tcp->th_seq,                    /* 序列号 */
                tcp->th_ack,                    /* 确认号 */
                TH_ACK | TH_PUSH,           /* Control flags */
                ntohs(tcp->th_win),       /* 窗口尺寸 */
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
        ntohs(ip->ip_id), //(u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
        0, /* frag 片偏移 */
        ip->ip_ttl, //(u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
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
        ethernet->ether_dhost, /* 以太网目的地址 */
        ethernet->ether_shost, /* 以太网源地址 */
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
	return (0);
}	



int main(int argc, char **argv)
{
	char *dev = NULL;		/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	pcap_t *handle;		/* packet capture handle */

	//char filter_exp[] = "dst 202.114.85.31 and tcp" host 101.251.200.84 and tcp and port 80;   
	char filter_exp[] = "host 101.251.200.84 and tcp and port 80";	/* filter expression [3] */
	struct bpf_program fp;	/* compiled filter program (expression) */
	bpf_u_int32 mask;		/* subnet mask */
	bpf_u_int32 net;		/* ip */
	int num_packets = 10;	/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
		printf("dev: %s\n", argv[1]);
	}
	else if (argc > 2) 
	{
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else 
	{
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
