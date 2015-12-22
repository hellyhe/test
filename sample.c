#include "./main.h"


int main(int argc, char **argv)
{
    pcap_t *pcapInt, *pcapExt;                      /* pcap descriptor */
    u_char *intPacket, *extPacket;
    int i;
    struct pcap_pkthdr intPkthdr, extPkthdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_code;
    bpf_u_int32 intLocalNet, intNetmask, extLocalNet;

    for(i=0;i to quit\n");

    /* read the configuration file and store it's data in an array */
    LIBXML_TEST_VERSION
    xmlNode *cur_node = xmlDocGetRootElement(xmlReadFile(((argv[1]) != NULL ? argv[1] : "conf.xml"), NULL, 0));
    strcpy(config.filter, "");

    XMLtoConf(cur_node);
    strcat(config.filter, " and not src host 192.168.191.137");
    printf("FILTER: %s\n", config.filter);


    /* get network number and mask associated with the internal capture device */
    if (pcap_lookupnet(config.intNIC, &intLocalNet, &intNetmask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            config.intNIC, errbuf);
        intLocalNet = 0;
        intNetmask = 0;
    }

    /* open internal capture device */
    pcapInt = pcap_open_live(config.intNIC, SNAP_LEN, 1, 1000, errbuf);
    if (pcapInt == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config.intNIC, errbuf);
        exit(EXIT_FAILURE);
    }
    /* open external capture device */
    pcapExt = pcap_open_live(config.extNIC, SNAP_LEN, 1, 1000, errbuf);
    if (pcapExt == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config.extNIC, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(pcapInt) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", config.intNIC);
        exit(EXIT_FAILURE);
    }
    if (pcap_datalink(pcapExt) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", config.extNIC);
        exit(EXIT_FAILURE);
    }

    /* compile the internal filter expression */
    if (pcap_compile(pcapInt, &filter_code, config.filter, 1, intLocalNet) == -1) { //adsvfhakdhvkahdvkadh
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            argv[1], pcap_geterr(pcapInt));
        exit(EXIT_FAILURE);
    }
    /* compile the external filter expression */
    if (pcap_compile(pcapExt, &filter_code, NULL, 1, extLocalNet) == -1) { //adsvfhakdhvkahdvkadh
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            argv[1], pcap_geterr(pcapExt));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled internal filter */
    if (pcap_setfilter(pcapInt, &filter_code) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            argv[1], pcap_geterr(pcapInt));
        exit(EXIT_FAILURE);
    }
     //apply the compiled external filter 
    if (pcap_setfilter(pcapExt, &filter_code) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            argv[1], pcap_geterr(pcapExt));
        exit(EXIT_FAILURE);
    }
    while (1 == 1)
    {     
        intPacket = (u_char*)pcap_next(pcapInt, &intPkthdr);
        extPacket = (u_char*)pcap_next(pcapExt, &extPkthdr);
        if (intPacket != NULL)
        {
            sniff(intPacket,0);
        } 
        if (extPacket != NULL)
        {
            sniff(extPacket,1);
        } 
    }

    printf("\nCapture complete.\n");
    /* cleanup */
    pcap_freecode(&filter_code);
    pcap_close(pcapInt);
    return (EXIT_SUCCESS);
}

int isStrBlank(unsigned char *s)
{
  if (!s || strcmp((char *)s, "") == 0) return 1;

  while(*s) {
    if ( (' ' != *s) && ('\n' != *s) && ('\r' != *s) && ('\t' != *s)) return 0;
    ++s;
  }
  return 1;
}

static void XMLtoConf(xmlNode* node)
{
     /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION
    xmlNode *cur_node = node;
    int i,flag=0;
    for (; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
                //if (isStrBlank(cur_node->children->content) == 1) continue;

                if (strcmp((char *)cur_node->name, "subnet_address") == 0){
                    strcat(config.filter, "src net ");
                    strcat(config.filter,(char *)cur_node->children->content);
                }
                //printf("1: %s", config.filter);
                if (strcmp((char *)cur_node->name, "NIC") == 0){
                    if (strcmp((char *)cur_node->parent->name, "internal") == 0){
                        config.intNIC = strdup((char *)cur_node->children->content);
                    }
                    else{
                        config.extNIC = strdup((char *)cur_node->children->content);
                    }
                }
                for (i = 0; strncmp((char *)cur_node->name, "machine_", 8) == 0; i++){

                    strcat(config.filter, " and not");
                    strcat(config.filter, " src host ");
                    flag=1;
                    strcat(config.filter, (char *)cur_node->children->content);
                    cur_node = cur_node->next;
                }


        }
        XMLtoConf(cur_node->children);
    }
    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();
    /*
     *  If device is NULL, that means the user did not specify one and is
     *  leaving it up libpcap to find one.
     */
}


void sniff(const u_char *packet , int flag)
{
    int i,x,tcpOpen=0;
    int protocol=-1; // 0- tcp, 1- udp, 2 -icmp
    tcp = (struct sniff_tcp*)(packet + 34); //skipping the ethernet and IP layers
    udp = (struct sniff_udp *)(packet + 34); //skipping the ethernet and IP layers
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    icmp = (struct sniff_icmp *)(packet+ 34);
    ether = (struct sniff_ethernet *)(packet);

    printf("/n1--%d/n",IP_HL(ip)*4);
    //if(ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80)
        //{

        if(ip->ip_p==IP_TYPE_TCP )
        {
            protocol = 0;
            payload_s = ntohs(ip->ip_len) - TH_OFF(tcp)*4 - IP_HL(ip)*4;

            if (payload_s)
                payload = (char* )(packet + SIZE_ETHERNET + TH_OFF(tcp)*4 + IP_HL(ip)*4);
            else
                payload = NULL;

        }
        else if(ip->ip_p == IP_TYPE_UDP){
            protocol = 1;
            payload_s = ntohs(ip->ip_len) - ntohs(udp->udp_len) - IP_HL(ip)*4;

            if (payload_s)
                payload = (char* )(packet + SIZE_ETHERNET + ntohs(udp->udp_len) + IP_HL(ip)*4);
            else
                payload = NULL;
        }
        else if(ip->ip_p == IP_TYPE_ICMP)
        {
            protocol = 2;
            payload_s = ntohs(ip->ip_len) - 8 - IP_HL(ip)*4;

            if (payload_s)
                payload = (char* )(packet + SIZE_ETHERNET + 8 + IP_HL(ip)*4);
            else
                payload = NULL;
        }   


            if(flag == 0)// we got a packet from the internal
            {
                if( ip->ip_p == IP_TYPE_TCP)
                {
                    for(i=0;iip_p)
                                if(nTable[i].ip_src.s_addr == ip->ip_src.s_addr)
                                    if(nTable[i].ip_dst.s_addr == ip->ip_dst.s_addr)
                                        if(ntohs(nTable[i].srcPort) == ntohs(tcp->th_sport))
                                            if(ntohs(nTable[i].dstPort) == ntohs(tcp->th_dport))
                                            {
                                                printf("we are in an open connection \n");
                                                changeSrcPacket(packet ,(i+2000)%8000 ,protocol);
                                                tcpOpen = 1;
                                                break;
                                            }
                    }           
                }
                if(tcpOpen == 0)
                {
                    for(i=0;iip_p == IP_TYPE_UDP ||ip->ip_p == IP_TYPE_TCP    )
                        {
                            if(nTable[i].free==0)
                            {
                                nTable[i].free=1;
                                nTable[i].ip_src = ip->ip_src;
                                nTable[i].ip_dst = ip->ip_dst;
                                nTable[i].srcPort = tcp->th_sport;
                                nTable[i].dstPort = tcp->th_dport;
                                nTable[i].protocol = ip->ip_p;
                                //printf("index : %d  ipsrc : %s  srcport : %d\n",i,inet_ntoa(nTable[i].ip_src),ntohs(nTable[i].srcPort));
                                ////////////change packet and send it with the src ip of the nat machine 
                                ///////////and the src port is (i+2000)%8000
                                changeSrcPacket(packet ,(i+2000)%8000 ,protocol);
                                break;
                            }
                        }
                        else
                        {
                            if(icmpTable[i].free == 0)
                            {
                                icmpTable[i].free=1;
                                icmpTable[i].ip_src = ip->ip_src;
                                icmpTable[i].ip_dst = ip->ip_dst;
                                icmpTable[i].protocol = ip->ip_p;
                                icmpTable[i].icmp_type = icmp->icmp_type;
                                icmpTable[i].icmp_id1 = icmp->icmp_id1;
                                changeSrcPacket(packet ,-1 ,protocol);
                                break;
                            }
                        }
                    }
                }
            }
            else // flag = 1
            {
            // we got a packet from the external. we want to send it to the right 
            // place in the internal

            //nTable[(tcp->th_dport-2000)%8000];

            //printf("dst: %d , src: %d \n",ntohs(tcp->th_dport),ntohs(tcp->th_sport));

                if(ip->ip_p== IP_TYPE_ICMP)
                {
                    changeDstPacket (packet,-1,protocol);
                }
                else
                {
                    for(x=0;xip_p == IP_TYPE_TCP)
                        {
                            if(((int)(ntohs(tcp->th_dport))-2000)%8000 == x && nTable[x].free == 1)
                            {
                                changeDstPacket (packet,x,protocol);
                                break;
                            }
                        }
                        else
                        {
                            if(((int)(ntohs(udp->udp_destport))-2000)%8000 == x && nTable[x].free == 1)
                            {
                                changeDstPacket (packet,x,protocol);
                                break;
                            }

                        }
                    }   
                }       
            // we create a packet with thw same src ip and port as we got
            // and only the dst port and ip will be the ones that are 
            //saved in nTable[(tcp->th_dport-2000)%8000]
            // now if it is in udp we will put 0 in nTable[(tcp->th_dport-2000)%8000].free


            }

}

void changeSrcPacket(const u_char *packet , int srcPort, int protocol)
{
    libnet_t *l;
    libnet_ptag_t ipv, ptag, popt,icmp;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t nat_adder;

     size_t ip_hlen=IP_HL(ip)*4;
     size_t ip_len=ntohs(ip->ip_len);

    size_t tcp_len = ip_len - ip_hlen;

    printf("\n%d %d %d %d",IP_HL(ip),ip_hlen,ip_len,tcp_len);


    icmp = ptag = ipv = LIBNET_PTAG_INITIALIZER;


     nat_adder = libnet_name2addr4(l,"192.168.191.137",LIBNET_DONT_RESOLVE);

     l = libnet_init(LIBNET_RAW4,config.extNIC, errbuf);

     if(protocol == 0)//TCP
     {

         if(TH_OFF(tcp)*4 > TCP_HEADER_SIZE)
         {
                options = (char*)packet + 54;
                options_s = TH_OFF(tcp)*4 - TCP_HEADER_SIZE;
                popt = libnet_build_tcp_options((u_int8_t*)options,options_s, l,0);     
         }

         ptag = libnet_build_tcp(
          srcPort, // source port
          ntohs(tcp->th_dport), // dest port
          htonl(tcp->th_seq), // sequence number
          ntohl(tcp->th_ack), // ack number
          tcp->th_flags, // flags
          ntohs(tcp->th_win), // window size
          0, // checksum
          ntohs(tcp->th_urp), // urg ptr
          TH_OFF(tcp)*4, // total length of the TCP packet
          (u_int8_t*)payload, // response
          payload_s, // response_length
          l, // libnet_t pointer
          ptag // ptag
          );


          printf("%d, %d, %d, %d, %d\n", TH_OFF(tcp)*4, IP_HL(ip)*4, payload_s, ntohs(ip->ip_len),TH_OFF(tcp)*4);
            if(ptag==-1)
             {
                fprintf(stderr, "Error building TCP header: %s\n",libnet_geterror(l));
                exit(1);
             }

    if (libnet_do_checksum(l, (u_int8_t*)ip,IPPROTO_TCP, TH_OFF(tcp)*4) udp_destport), /* destination port */
                udp->udp_len, /* packet length */
                0, /* checksum */
                (u_int8_t*)payload, /* payload */
                payload_s, /* payload size */
                l, /* libnet handle */
                ptag); /* libnet id */

          if(ptag==-1)
          {
             fprintf(stderr, "Error building UDP header: %s\n",libnet_geterror(l));
             exit(1);
          }

     }

   // if(protocol == 2)//ICMP
     //{
        ///add functions of icmp
     // icmp = libnet_build_icmpv4_echo(
        //ICMP_ECHO, /* type */
        //0, /* code */
        //0, /* checksum */
        //icmp->icmp_id1, /* id */
        //icmp->icmp_seq1, /* sequence number */
        //payload, /* payload */
        //payload_s, /* payload size */
        //l, /* libnet context */
        //icmp); /* ptag */

        //if (icmp == -1)
        //{
        //  fprintf(stderr, "Can't build ICMP header: %s\n",
        //  libnet_geterror(l));

        //}
    // }


       ipv = libnet_build_ipv4(
                                                /* total length */
                   ntohs(ip->ip_len),
                    ip->ip_tos,                          /* type of service */
                    ntohs(ip->ip_id),                        /* identification */
                    ntohs(ip->ip_off),                          /* fragmentation */
                    ip->ip_ttl,                         /* time to live */
                    ip->ip_p,                /* protocol */
                    0,                          /* checksum */
                    nat_adder,                     /* (Nat) source */
                    ip->ip_dst.s_addr,                     /* destination */
                   NULL,                       /* payload */
                   0,                          /* payload size */
                    l,                          /* libnet handle */
                    0);                         /* ptag */

        if(ipv == -1)
        {
            fprintf(stderr,"Error building IP header: %s\n", libnet_geterror(l));
            exit(1);
        }

        /*if (libnet_do_checksum(l, (u_int8_t*)l, IPPROTO_IP, ntohs(ip->ip_len) + payload_s) th_flags == 0x01)
            {
                nTable[index].fin++;
            }
            if(tcp->th_flags == 0x11 && nTable[index].fin == 1)
            {
                nTable[index].fin++;
            }
            if(tcp->th_flags == 0x10 && nTable[index].fin == 2)
            {
                nTable[index].free = 0; 
                nTable[index].fin = 0;
            }
        }


         // Fix IP header checksum
  //  ip->ip_sum = 0;
    if (libnet_do_checksum(l, (u_int8_t*)ip,IPPROTO_IP, IP_HL(ip)*4) th_sport),ntohs(nTable[index].srcPort));
    printf("src ip : %s    dst ip: %s\n",inet_ntoa(ip->ip_src), inet_ntoa(nTable[index].ip_src));

    ptag = ipv = LIBNET_PTAG_INITIALIZER;

    if(protocol == 0 || protocol == 1) // udp or tcp
    {

        if(nTable[index].free == 1)
        {
            l = libnet_init(LIBNET_RAW4,config.intNIC, errbuf);

            if(protocol == 0 ) //TCP
            {

                if(TH_OFF(tcp)*4 > TCP_HEADER_SIZE)
                {
                     options = (char*)packet + 54;
                     options_s = TH_OFF(tcp)*4 - TCP_HEADER_SIZE;
                     popt = libnet_build_tcp_options((u_int8_t*)options,options_s, l,0);

                }

                  ptag = libnet_build_tcp(
                  ntohs(tcp->th_sport), // source port
                  ntohs(nTable[index].srcPort), // dest port
                  ntohl(tcp->th_seq), // sequence number
                  ntohl(tcp->th_ack), // ack number
                  tcp->th_flags, // flags
                  ntohs(tcp->th_win), // window size
                  0, // checksum
                  ntohs(tcp->th_urp), // urg ptr
                  TH_OFF(tcp)*4, // total length of the TCP packet
                  (u_int8_t*)payload, // response
                  payload_s, // response_length
                  l, // libnet_t pointer
                  ptag // ptag
                  );

                  if(ptag==-1)
                  {
                    fprintf(stderr, "Error building TCP header: %s\n",libnet_geterror(l));
                    exit(1);
                  }
            }

            if(protocol == 1)// UDP
            {
                ptag = libnet_build_udp(
                    ntohs(udp->udp_srcport), /* source port */
                    ntohs(nTable[index].srcPort), /* destination port */
                    udp->udp_len, /* packet length */
                    0, /* checksum */
                    (u_int8_t*)payload, /* payload */
                    payload_s, /* payload size */
                    l, /* libnet handle */
                    ptag); /* libnet id */

                if(ptag==-1)
                {
                    fprintf(stderr, "Error building UDP header: %s\n",libnet_geterror(l));
                    exit(1);
                }
            }
        }
    }
    if(protocol == 2) // ICMP
    {
        for(i=0;i icmp_type)
                    if(icmpTable[i].ip_dst.s_addr == ip->ip_src.s_addr)
                        if(icmpTable[i].icmp_id1 == icmp->icmp_id1)
                        {
                            index = i;
                            break;
                        }

        }

        ///add functions of icmp

    }

              ipv = libnet_build_ipv4(
                                                        /* total length */
                            ntohs(ip->ip_len),
                            ip->ip_tos,                          /* type of service */
                            ntohs(ip->ip_id),                        /* identification */
                            ntohs(ip->ip_off),                          /* fragmentation */
                            ip->ip_ttl,                         /* time to live */
                            ip->ip_p,                /* protocol */
                           0,                           /* checksum */
                            ip->ip_src.s_addr,                     /* (Nat) source */
                            nTable[index].ip_src.s_addr,                     /* destination */
                            NULL,                       /* payload */
                            0,                          /* payload size */
                            l,                          /* libnet handle */
                            0);                          /* ptag */
               if(ipv == -1)
              {
                fprintf(stderr,"Error building IP header: %s\n", libnet_geterror(l));
                exit(1);
              }   

            /*if (libnet_do_checksum(l, (u_int8_t*)l, IPPROTO_IP, ntohs(ip->ip_len) + payload_s) th_flags == 0x01)
                    {
                        nTable[index].fin++;
                    }
                    if(tcp->th_flags == 0x11 && nTable[index].fin == 1)
                    {
                        nTable[index].fin++;
                    }
                    if(tcp->th_flags == 0x10 && nTable[index].fin == 2)
                    {
                        nTable[index].free = 0; 
                        nTable[index].fin = 0;
                    }
                }
                else
                {
                    nTable[index].free = 0; 
                    nTable[index].fin = 0;
                }
            }


            if ( libnet_write(l) == -1 )
                      fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(l));
            libnet_destroy(l);

}
