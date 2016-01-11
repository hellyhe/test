#include <stdio.h>
#include <string.h>

struct me_config
{
    bool bfilter;
    u_int8_t cpucore;
    u_int8_t nodes;
    u_int8_t threads;
    u_char *send_name;
    u_char *send_mac;
    u_char *recv_name;
    u_char *recv_mac;
    u_int8_t recv_thread;
    u_char *route_mac;
}

struct me_white_uri
{
    u_char *uri;
    u_int8_t percent;
    u_char *tag;
}

struct me_src_addr
{
    u_char *url_regex;   
}

struct me_dst_addr
{
    u_char *url;
    u_int8_t percent;  
    u_int8_t type;
    u_int8_t gzip;
    u_char *head;
    u_char *mime;
    u_char *file;
}

struct me_task
{
    u_char *host;
    u_int8_t iptaskexpire;
    me_white_uri[] white_uris;
    me_src_addr src_addr;
    me_dst_addr[] dst_addrs;
}

//http://c.biancheng.net/cpp/html/93.html

me_config me_cfg;

me_task[] me_tasks;

void getconfig(u_char *xmlfile);

