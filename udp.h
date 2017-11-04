u_int16_t UdpChecksum(struct in_addr *saddr,struct in_addr *daddr,
						u_int8_t proto,u_int8_t *data,int len);
int Udp(int UpperLen,u_char *UpperPkt,char *psrc,char *pdst,u_int16_t sport,
		u_int16_t dport);
