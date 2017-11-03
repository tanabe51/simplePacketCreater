#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netpacket/packet.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <time.h>
#include <netinet/in.h>
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "checksum.h"

u_int16_t TcpChecksum(struct in_addr *saddr,struct in_addr *daddr,u_int8_t protocol,u_int8_t *data,int len)
{
	struct pseudo_ip p_ip;
	u_int16_t sum;
	memset(&p_ip,0,sizeof(struct pseudo_ip));
	p_ip.ip_src.s_addr = saddr->s_addr; 
	p_ip.ip_dst.s_addr = daddr->s_addr; 
	p_ip.ip_p = protocol; 
	p_ip.dummy = 0;
	p_ip.ip_len = htons(sizeof(struct tcphdr)); 
	sum = checksum2((u_int8_t *)&p_ip,sizeof(struct pseudo_ip),data,len);
	return sum;
}

int Tcp(int UpperLen,u_char *UpperPkt,char *psrc,char *pdst,u_int16_t sport,u_int16_t dport)
{
	u_char Upper[1500];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);
	
	srand(time(NULL));

	struct tcphdr *tcp;
	u_int8_t *ptr;
	
	ptr = (u_int8_t*)UpperPkt;
	tcp = (struct tcphdr *)ptr;
	memset(tcp,0,sizeof(struct iphdr));
	tcp->source = htons(sport);
	tcp->dest = htons(dport);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = 1;
	tcp->fin = 0;
	tcp->window = htons(5000);
	tcp->urg_ptr = 0;
	
	struct in_addr psrc2;
	struct in_addr pdst2;
	psrc2.s_addr = inet_addr(psrc);
	pdst2.s_addr = inet_addr(pdst);
	
	tcp->check = TcpChecksum(&psrc2,&pdst2,IPPROTO_TCP,UpperPkt,sizeof(struct tcphdr));

	ptr += sizeof(struct tcphdr);
	memcpy(ptr,Upper,UpperLen);
	ptr += UpperLen;
	return UpperLen+sizeof(struct tcphdr);
}

