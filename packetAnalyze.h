struct packetInformation{
	//for ether packet
	char hsrc[18];
	char hdst[18];
	
	//for ip packet
	char psrc[16];
	char pdst[16];

	//for tcp packet
	u_int16_t source;
	u_int16_t dest;
	u_int32_t seq;
	u_int32_t ack_seq;
	u_int16_t res1:4;
	u_int16_t doff:4;
	u_int16_t fin:1;
	u_int16_t syn:1;
	u_int16_t rst:1;
	u_int16_t psh:1;
	u_int16_t ack:1;
	u_int16_t urg:1;
	u_int16_t res2:2;
};





u_int16_t AnalyzeTcp(u_char *data,int size,struct packetInformation *packInfo);
u_int16_t AnalyzeIp(u_char *data,int size,struct packetInformation *packInfo);
u_int16_t Analyze(u_char *data,int size,struct packetInformation *packInfo);
