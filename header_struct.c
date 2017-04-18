struct eth_header
{
	//目的MAC
	unsigned char dest_mac[6] ;
	//源MAC
	unsigned char source_mac[6] ;
	//协议号 0x0800为IP报文协议号
	unsigned char ethhdr_protocol[2] ;
} ;

struct ipv6_header
{
	unsigned char	TrafficClass0 : 4 ,
			Version : 4 ;
	unsigned char	FlowLabel0 : 4 ,
			TrafficClass1 : 4 ;
	unsigned char	FlowLabel1[2] ;
	unsigned char	PayloadLength[2] ;
	unsigned char	NextHeader ;
	unsigned char	HopLimit ;
	unsigned char	SourceAddress[16] ;
	unsigned char	DestAddress[16] ;
};

struct ip_header
{
	unsigned char 	HeaderLength : 4 ,	//IP报文长度 该字段 * 4 = IP报文长度
			Version : 4 ;		//版本号 0x4 IPV4  0x6 IPV6
	unsigned char	tos ;			//服务类型 Type of Service
	unsigned char	TotalLength[2] ;	//IP报文总长 IP报文+TCP报文+数据段
	unsigned char	Identifier[2] ;		//标识符
	unsigned char	FlagsFargmentOffset[2];	//标记 3个比特位 中间一位=1表示不分片 片偏移占13个bit
	unsigned char	TimeToLive ;		//生存时间
	unsigned char	Protocol ;		//协议 TCP协议为0x06
	unsigned char	checksum[2] ;		//校验和
	unsigned char	SourceAddress[4] ;	//源IP
	unsigned char	DestAddress[4] ;	//目的IP
} ;

struct tcp_header
{
	unsigned char	SourcePort[2] ;		//源端口
	unsigned char	DestPort[2] ;		//目的端口
	unsigned char	Seq[4] ;
	unsigned char	AckSeq[4] ;
	unsigned char	doff_1: 4 ,		//保留位
			HeaderLength : 4 ;	//4位首部长度
	unsigned char	FIN : 1 ,
			SYN : 1 ,
			PST : 1 ,
			PSH : 1 ,
			ACK : 1 ,
			URG : 1 ,
			doff_2 : 2 ;		//保留位
	unsigned char	win[2] ;		//窗口大小
	unsigned char	checksum[2] ;		//校验和
	unsigned char	SurgentPointer[2] ;	//紧急数据偏移量
} ;

struct udp_header
{
	unsigned char SourcePort[2] ;
	unsigned char DestPort[2] ;
	unsigned char usLength[2] ;
	unsigned char checksum[2] ;
} ;

struct icmp_header
{
	unsigned char Types ;
	unsigned char Code ;
	unsigned char checksum[2] ;
} ;

struct icmp_header_ping
{
	unsigned char Types ;
	unsigned char Code ;
	unsigned char checksum[2] ;
	unsigned char Identifier[2] ;
	unsigned char Seq[2] ;
} ;

struct arp_header
{
	unsigned char HardwareType[2] ;
	unsigned char Protocol[2] ;
	unsigned char MAC_LEN ;
	unsigned char IPADDRESS_LEN ;
	unsigned char Operation[2] ;
	unsigned char SourceMAC[6] ;
	unsigned char SourceAddress[4] ;
	unsigned char DestMAC[6] ;
	unsigned char DestAddress[4] ;
} ;

struct dns_header
{
	unsigned char	id[2] ;
	unsigned char	RD : 1 ,
			TC : 1 ,
			AA : 1 ,
			opcode : 4 ,
			QR : 1 ;
	unsigned char	rcode : 4 ,
			zero : 3 ,
			RA : 1 ;
	unsigned char	Questions[2] ;	//问题数
	unsigned char	Answer[2] ;	//回答数
	unsigned char	Authority[2] ;	//授权数
	unsigned char	Additional[2] ;	//附加数
} ;
