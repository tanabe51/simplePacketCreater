#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "checksum.h"
#include "packetAnalyze.h"

u_int16_t AnalyzeTcp(u_char *data,int size,struct packetInformation *packInfo)
{

	u_char *ptr;
	int lest;
	struct tcphdr *tcp;

	ptr = data;
	lest = size;
	
	if(lest<sizeof(struct tcphdr)){
		fprintf(stderr,"too short(tcp)\n");
		return -1;
	}
	tcp = (struct tcphdr *)ptr;

	return ntohs(tcp->source);
}


u_int16_t AnalyzeIp(u_char *data,int size,struct packetInformation *packInfo)
{
	u_char *ptr;
	int lest;
	struct iphdr *ip;
	u_char *option;
	int optionLen,len;
	unsigned short sum;

	ptr = data;
	lest = size;

	if(lest<sizeof(struct iphdr)){
		fprintf(stderr,"too short(ip)\n");
		return -1;
	}
	ip = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	lest -= sizeof(struct iphdr);

	char *src;
	char *dst;

	src = inet_ntoa(*(struct in_addr *)&ip->saddr);
	memcpy(packInfo->psrc,src,16);
	dst = inet_ntoa(*(struct in_addr *)&ip->daddr);
	memcpy(packInfo->pdst,dst,16);


	optionLen = ip->ihl*4 - sizeof(struct iphdr);
	if(optionLen>0){
		if(optionLen>=1500){
			fprintf(stderr,"too long ipOption\n");
			return -1;
		}
		option = ptr;
		ptr += optionLen;
		lest -=optionLen;
	}

	if(checkIPchecksum(ip,option,optionLen)==0){
		fprintf(stderr,"bad ip checksum\n");
		return -1;
	}
	
	u_int16_t sport = 0;
	if(ip->protocol==0x06){
		sport = AnalyzeTcp(ptr,lest,packInfo);
	}
	return sport;
}


u_int16_t Analyze(u_char *data,int size,struct packetInformation *packInfo)
{
	u_char *ptr;
	int lest;
	struct ether_header *eh;

	ptr = data;
	lest = size;

	if(lest<sizeof(struct ether_header)){
		fprintf(stderr,"too short(ether)\n");
		return -1;
	}
	eh = (struct ether_header *)ptr;
	ptr +=sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	ether_ntoa_r((struct ether_addr *)eh->ether_shost,packInfo->hsrc);
	ether_ntoa_r((struct ether_addr *)eh->ether_dhost,packInfo->hdst);

	u_int16_t sport = 0;
	if(ntohs(eh->ether_type)==0x0800){
		sport = AnalyzeIp(ptr,lest,packInfo);
	}

	return sport;
}
