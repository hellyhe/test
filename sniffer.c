#define __USE_BSD
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define MAXBYTES2CAPTURE 2048

int TCP_RST_send(tcp_seq seq, tcp_seq ack, unsigned long src_ip, unsigned long dst_ip, u_short src_prt, u_short dst_prt, u_short win)
{
	return 0;
}

int main(int argc, char * argv[])
{
	int count = 0;
	bpf_u_int32 netaddr = 0, mask = 0;
	pcap_t *descr = NULL;
	struct bpf_program filter;
	struct ip *iphdr = NULL;
	struct tcphdr *tcphdr = NULL;
	struct pcap_pkthdr pkthdr;
	const unsigned char *packet = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	if( argc != 2)
	{
		printf("USAGE: tcpsyndos <interface>\n");
		exit(1);
	}
	
	//descr = pcap_open_live(argv[1], &netaddr, &mask, errbuf);
	descr = pcap_open_live(argv[1], &netaddr, 1, &mask, errbuf);
	
	pcap_compile(descr, &filter, "(tcp[13] == 0x10) or tcp[13] == 0x18)", 1, mask);
	pcap_setfilter(descr, &filter);
	
	while(1)
	{
		packet = pcap_next(descr, &pkthdr);
		iphdr = (struct ip *)(packet + 14);
		tcphdr = (struct tcphdr *)(packet + 14 + 20);
		printf("+---------------------------------------------------------------+\n");
		printf("Received Packet %d:\n", ++count);
		printf("ack: %u\n", ntohl(tcphdr->th_ack));
		printf("seq: %u\n", ntohl(tcphdr->th_seq));
		printf("dst ip: %s\n", inet_ntoa(iphdr->ip_dst));
		printf("src ip: %s\n", inet_ntoa(iphdr->ip_src));
		printf("src port: %d\n", ntohs(tcphdr->th_sport));
		printf("dst port: %d\n", ntohs(tcphdr->th_dport));
		printf("\n");
		
		//TCP_RST_send(tcphdr->thack, 0, iphdr_ip_dst.s_addr, iphdr->ip_src.s_addr, tcphdr->thdport, tcphdr->th_sport, 0);
	}
	return 0;
}
