#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "checksum.h"

u_int16_t UdpChecksum(struct in_addr *saddr,struct in_addr *daddr,
						u_int8_t proto,u_int8_t *data,int len)
{
	struct pseudo_ip p_ip;
	u_int16_t sum;
		memset(&p_ip,0,sizeof(struct pseudo_ip));
		p_ip.ip_src.s_addr=saddr->s_addr;
		p_ip.ip_dst.s_addr=daddr->s_addr;
		p_ip.ip_p=proto;
		p_ip.ip_len=htons(len);

		sum=checksum2((u_int8_t *)&p_ip,sizeof(struct pseudo_ip),data,len);
		if(sum==0x0000){
			sum=0xFFFF;
		}
		return sum;
}

int Udp(int UpperLen,u_char *UpperPkt,char *psrc,char *pdst,u_int16_t sport,u_int16_t dport)
{
	u_char Upper[1500-sizeof(struct iphdr)-sizeof(struct ether_header)];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);

	struct udphdr *udp;
	u_int8_t *ptr;
		
	ptr = (u_int8_t *)UpperPkt;
	udp = (struct udphdr *)ptr;
	memset(udp,0,sizeof(struct udphdr));
	udp->source = htons(sport);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(struct udphdr)+UpperLen);
	udp->check = 0;

	struct in_addr psrc2;
	struct in_addr pdst2;
	psrc2.s_addr = inet_addr(psrc);
	pdst2.s_addr = inet_addr(pdst);
	udp->check = UdpChecksum(&psrc2,&pdst2,IPPROTO_UDP,UpperPkt,sizeof(struct udphdr));


	ptr += sizeof(struct udphdr);
	memcpy(ptr,Upper,UpperLen);
	ptr += UpperLen;
	return UpperLen+sizeof(struct udphdr);
}

