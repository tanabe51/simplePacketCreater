struct pseudo_ip{
	struct in_addr ip_src;
	struct in_addr ip_dst;
	u_int8_t dummy;
	u_int8_t ip_p;
	u_int16_t ip_len;
};

u_int16_t TcpChecksum(struct in_addr *saddr,struct in_addr *daddr,u_int8_t protocol,u_int8_t *data,int len);
int Tcp(int UpperLen,u_char *UpperPkt,char *psrc,char *pdst,u_int16_t sport,u_int16_t dport);

