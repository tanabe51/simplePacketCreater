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
#include "ether.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"


int main(int argc,char *argv[])
{
	u_int8_t pkt[1514];
	int driver;
	int len;
	char *hdst = "52:54:00:12:35:02";
	char *hsrc = "08:00:27:66:5d:29";
	char *psrc = "10.0.2.15";
	char *pdst = "10.0.2.2";
	printf("%ld\n",strlen((const char *)pkt));

	driver = DriverUp(argv[1],0,0);
	len = Ether(Arp(0,pkt,),pkt,hdst,hsrc,0x0800);
	write(driver,pkt,len);

	return 0;
}
