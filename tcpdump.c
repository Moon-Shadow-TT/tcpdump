# include <stdio.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <linux/if_ether.h>
# include <malloc.h>
# include <arpa/inet.h>
# include <string.h>
# include <stdlib.h>
# include <signal.h>
# include "header_struct.c"

# define BUFLEN 0xA00000

extern unsigned int change_16(char ah,char al) ;
extern unsigned int change_32(char c_32 ,char c_24 , char c_16 , char c_8) ;
int check_argv_port(char *port);
int check_argv_host(char *host);
int check_argv(int argc , char **argv);
void print_usage(void) ;
void mysignal(int sig) ;

void ipv4(void);
void ipv6(void);
void tcp(void);
void udp(void);
void icmp(void);
void arp(void);
void dns(void);

void print_time(void);
void print_data_char(void);
void print_all_hex(void);
void print_eth_details(void);
void print_iph_details(void);
void print_tcp_details(void);
void print_udp_details(void);
void print_ip_address(void);
void print_iph_details_IPv6(void) ;
void print_ip_address_IPv6(void) ;
void print_port_tcp_or_udp(void);
void print_message(void) ;
void print_icmp_details(void) ;
void print_dns_details(void) ;
void print_arp_details(void) ;
int  print_dns_rcode(unsigned char *dnshdr , int len) ;
void print_address_ipv6(unsigned char *ip) ;

int Flag_arp = 1 ;
int Flag_IPv6 = 1 ;
int Flag_IPv4 = 1 ;
int Flag_TCP = 1 ;
int Flag_UDP = 1 ;
int Flag_ICMP = 1 ;
int Flag_dns = 0 ;
int Flag_IP_Version = 0 ;
int Flag_Protocol = 0 ;
int Flag_dns_udp = 0 ;
int Flag_dns_tcp = 0 ;
int data_char = 0 ;
int all_hex = 0 ;
int v = 0 ;
int Flag_tcpdump = 0 ;

unsigned int *IPv4_list = 0 ;
unsigned int IPv4_list_num = 0 ;
unsigned char **IPv6_list = 0 ;
unsigned int IPv6_list_num = 0 ;
unsigned int *PORT_list = 0 ;
unsigned int PORT_list_num = 0 ;
unsigned char *buf ;
int sockfd = -1 ;
int recv_len = 0 ;
int recv_num = 0 ;
int received_num = 0 ;

struct eth_header *ethhdr = NULL ;
struct ip_header *iphdr = NULL ;
struct ipv6_header *ipv6hdr = NULL ;
struct tcp_header *tcphdr = NULL ;
struct udp_header *udphdr = NULL ;
struct icmp_header *icmphdr = NULL ;
struct arp_header *arphdr = NULL ;
struct dns_header *dnshdr = NULL ;

unsigned int IPHeaderLength ;
unsigned int TCPHeaderLength ;
unsigned int UDPHeaderLength ;
unsigned int DataOffset ;
unsigned int SourcePort ;
unsigned int DestPort ;
unsigned int flag ;
unsigned short FargmentOffset ;
unsigned int SourceAddress ;
unsigned int DestAddress ;

int main(int argc , char **argv)
{
	if(argc > 1)
	{
		if ( check_argv(argc , argv) == 1 )
		{
			free(IPv4_list) ;
			free(IPv6_list) ;
			free(PORT_list) ;
			return 1 ;
		}
	}
	signal(SIGINT,mysignal) ;
	buf = (char *)malloc(BUFLEN) ;
	sockfd = socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL)) ;
	if (sockfd == -1)
	{
		printf("socket faild\n") ;
		return 1 ;
	}

	while(1)
	{
		recv_len = recvfrom(sockfd,buf,BUFLEN,MSG_TRUNC,NULL,NULL) ;
		if(recv_len == -1)
		{
			printf("recvfrom faild\n") ;
			return 1 ;
		}
		ethhdr = (struct eth_header *)buf ;
		if((ethhdr->ethhdr_protocol[0] == 0x08) && (ethhdr->ethhdr_protocol[1] == 0x00) && (Flag_IPv4 == 1))
		{
			iphdr = (struct ip_header *)&buf[sizeof(struct eth_header)] ;
			Flag_IP_Version = iphdr->Version ;
			ipv4() ;
		}
		else if((ethhdr->ethhdr_protocol[0] == 0x86) && (ethhdr->ethhdr_protocol[1] == 0xDD) && (Flag_IPv6 == 1))
		{
			IPHeaderLength = 40 ;
			ipv6hdr = (struct ipv6_header *)&buf[sizeof(struct eth_header)] ;
			Flag_IP_Version = ipv6hdr->Version ;
			ipv6() ;
		}
		else if((ethhdr->ethhdr_protocol[0] == 0x08) && (ethhdr->ethhdr_protocol[1] == 0x06) && (Flag_arp == 1))
		{
			arphdr = (struct arp_header *)&buf[sizeof(struct eth_header)] ;
			arp() ;
		}
		fflush(stdout) ;
	}

	return 0 ;
}

void mysignal(int sig)
{
	int n ;
	for(n=0;n<IPv6_list_num;n++)
	{
		free(IPv6_list[n]) ;
	}
	free(IPv4_list) ;
	free(IPv6_list) ;
	free(PORT_list) ;
	free(buf) ;
	close(sockfd) ;
	printf("\n\n%d packets received\n",received_num) ;
	exit(0) ;
}

void print_port_tcp_or_udp(void)
{
	printf("Source Port : %d\n",SourcePort) ;
	printf("Dest   Port : %d\n",DestPort) ;
}

void print_tcp_details(void)
{
	print_port_tcp_or_udp() ;
	printf("    Seq : %ld\n",change_32(tcphdr->Seq[0],tcphdr->Seq[1],tcphdr->Seq[2],tcphdr->Seq[3])) ;
	printf("Ack Seq : %ld\n",change_32(tcphdr->AckSeq[0],tcphdr->AckSeq[1],tcphdr->AckSeq[2],tcphdr->AckSeq[3])) ;
	printf("TCP Header Length : %d\n",TCPHeaderLength) ;
	printf("URG : %d\n",tcphdr->URG) ;
	printf("ACK : %d\n",tcphdr->ACK) ;
	printf("PSH : %d\n",tcphdr->PSH) ;
	printf("PST : %d\n",tcphdr->PST) ;
	printf("SYN : %d\n",tcphdr->SYN) ;
	printf("FIN : %d\n",tcphdr->FIN) ;
	printf("window : %d\n",change_16(tcphdr->win[0],tcphdr->win[1])) ;
	printf("tcp checksum : %d\n",change_16(tcphdr->checksum[0],tcphdr->checksum[1])) ;
	printf("Surgent Pointer : %d\n",change_16(tcphdr->SurgentPointer[0],tcphdr->SurgentPointer[1])) ;
}

void print_ip_address(void)
{
	int n ;
	printf("Source Address : ") ;
	for(n=0;n<3;n++)
	{
		printf("%d.",iphdr->SourceAddress[n]) ;
	}
	printf("%d\n",iphdr->SourceAddress[n]) ;
	printf("Dest   Address : ") ;
	for(n=0;n<3;n++)
	{
		printf("%d.",iphdr->DestAddress[n]) ;
	}
	printf("%d\n",iphdr->DestAddress[n]) ;
}

void print_address_ipv6(unsigned char *ip)
{
	int n , x , y , flag ;
	for(flag=0,x=0,n=0;n<16;n+=2)
	{
		if((flag==0)&&(ip[n]==0x00)&&(ip[n+1]==0x00)&&(ip[n+2]==0x00)&&(ip[n+3]==0x00))
		{
			flag = 1 ;
			n += 4 ;
			printf(":") ;
			for(y=n;y<16;y+=2)
			{
				if((ip[y]==0x00)&&(ip[y+1]==0x00))
				{
					n += 2 ;
				}
				else
				{
					break ;
				}
			}
		}
		if((ip[n] == 0x00)&&(ip[n+1] == 0x00))
		{
			printf("0") ;
		}
		else
		{
			if(ip[n] != 0x00)
			{
				printf("%x%02x",ip[n],ip[n+1]) ;
			}
			else if(ip[n+1] != 0x00)
			{
				printf("%x",ip[n+1]) ;
			}
		}
		if(n<14)
		{
			printf(":") ;
		}
	}
}

void print_ip_address_IPv6(void)
{
	printf("SourceAddress : ") ;
	print_address_ipv6(ipv6hdr->SourceAddress) ;
	printf("\n") ;
	printf("DestAddress   : ") ;
	print_address_ipv6(ipv6hdr->DestAddress) ;
	printf("\n") ;
}

void print_iph_details_IPv6(void)
{
	printf("Version : %d\n",ipv6hdr->Version) ;
	printf("TrafficClass : %d\n",change_16(ipv6hdr->TrafficClass0,ipv6hdr->TrafficClass1)) ;
	printf("FlowLabel : %d\n",change_32(0,ipv6hdr->FlowLabel0,ipv6hdr->FlowLabel1[0],ipv6hdr->FlowLabel1[1])) ;
	printf("PayloadLength : %d\n",change_16(ipv6hdr->PayloadLength[0],ipv6hdr->PayloadLength[1])) ;
	printf("NextHeader : %d\n",ipv6hdr->NextHeader) ;
	printf("HopLimit : %d\n",ipv6hdr->HopLimit) ;
	print_ip_address_IPv6() ;
}

void print_iph_details(void)
{
	printf("IP Header Length : %d涓瓧鑺俓n",IPHeaderLength) ;
	printf("Version : 0x%02X\n",iphdr->Version) ;
	//printf("Version = 0x04 琛ㄧず IPV4\n") ;
	printf("tos : %d\n",iphdr->tos) ;
	printf("Total Length : %d\n",change_16(iphdr->TotalLength[0],iphdr->TotalLength[1])) ;
	printf("Identifier : %d\n",change_16(iphdr->Identifier[0],iphdr->Identifier[1])) ;
	printf("Flags : %d\n",(iphdr->FlagsFargmentOffset[0])>>5) ;
	FargmentOffset = change_16(iphdr->FlagsFargmentOffset[0],iphdr->FlagsFargmentOffset[1]) ;
	FargmentOffset = FargmentOffset << 3 ;
	FargmentOffset = FargmentOffset >> 3 ;
	printf("FargmentOffset : %d\n",FargmentOffset) ;
	printf("Time To Live : %d\n",iphdr->TimeToLive) ;
	printf("ip header protocol : %d\n",iphdr->Protocol) ;
	printf("ip checksum : %d\n",change_16(iphdr->checksum[0],iphdr->checksum[1])) ;
	print_ip_address() ;
}

void print_eth_details(void)
{
	int n ;
	printf("Dest   MAC : ") ;
	for(n=0;n<5;n++)
	{
		printf("%02X:",ethhdr->dest_mac[n]) ;
	}
	printf("%02X\n",ethhdr->dest_mac[n]) ;
	printf("Source MAC : ") ;
	for(n=0;n<5;n++)
	{
		printf("%02X:",ethhdr->source_mac[n]) ;
	}
	printf("%02X\n",ethhdr->source_mac[n]) ;
	printf("eth header protocol : 0x") ;
	printf("%02X",ethhdr->ethhdr_protocol[0]) ;
	printf("%02X\n",ethhdr->ethhdr_protocol[1]) ;
	//printf("0x0800琛ㄧずIP鎶ユ枃\n") ;
}

void print_udp_details(void)
{
	print_port_tcp_or_udp() ;
	printf("usLength : %d\n" , change_16(udphdr->usLength[0],udphdr->usLength[1])) ;
	//udp鎶ユ枃闀垮害+鏁版嵁娈甸暱搴?	printf("checksum : %d\n" , change_16(udphdr->checksum[0],udphdr->checksum[1])) ;
}

void print_icmp_details(void)
{
	struct icmp_header_ping *icmphdr_ping ;
	printf("Recv Message Size : %d\n",recv_len) ;
	printf("ICMP Types : %d\n",icmphdr->Types) ;
	printf("ICMP Code : %d\n",icmphdr->Code) ;
	printf("ICMP CheckSum : %d\n",change_16(icmphdr->checksum[0],icmphdr->checksum[1])) ;
	DataOffset = sizeof(struct eth_header) + IPHeaderLength + sizeof(struct icmp_header) ;
	if(Flag_Protocol == 0x3A)
	{
		if(((icmphdr->Types == 0x80) || (icmphdr->Types == 0x81)) && (icmphdr->Code == 0x00))
		{
			icmphdr_ping = (struct icmp_header_ping *)icmphdr ;
			printf("ICMP PING Identifier : %d\n",change_16(icmphdr_ping->Identifier[0],icmphdr_ping->Identifier[1]));
			printf("ICMP Seq : %d\n",change_16(icmphdr_ping->Seq[0],icmphdr_ping->Seq[1])) ;
			printf("ICMP Lengths : %d\n",recv_len - sizeof(struct eth_header) - IPHeaderLength) ;
			printf("Data Lengths : %d\n",recv_len - sizeof(struct eth_header) - IPHeaderLength - sizeof(struct icmp_header_ping)) ;
			DataOffset = sizeof(struct eth_header) + IPHeaderLength + sizeof(struct icmp_header_ping) ;
		}
	}
	else if(Flag_Protocol == 0x01)
	{
		if(((icmphdr->Types == 0x00) || (icmphdr->Types == 0x08)) && (icmphdr->Code == 0x00))
		{
			icmphdr_ping = (struct icmp_header_ping *)icmphdr ;
			printf("ICMP PING Identifier : %d\n",change_16(icmphdr_ping->Identifier[0],icmphdr_ping->Identifier[1]));
			printf("ICMP Seq : %d\n",change_16(icmphdr_ping->Seq[0],icmphdr_ping->Seq[1])) ;
			printf("ICMP Lengths : %d\n",recv_len - sizeof(struct eth_header) - IPHeaderLength) ;
			printf("Data Lengths : %d\n",recv_len - sizeof(struct eth_header) - IPHeaderLength - sizeof(struct icmp_header_ping)) ;
			DataOffset = sizeof(struct eth_header) + IPHeaderLength + sizeof(struct icmp_header_ping) ;
		}
	}
}

void print_dns_type(unsigned short int type)
{
	switch (type)
	{
		case 1 : printf("A") ; break ;
		case 2 : printf("NS") ; break ;
		case 5 : printf("CNAME") ; break ;
		case 6 : printf("SOA") ; break ;
		case 11 : printf("WKS") ; break ;
		case 12 : printf("PTR") ; break ;
		case 13 : printf("HINFO") ; break ;
		case 15 : printf("MX") ; break ;
		case 28 : printf("AAAA") ; break ;
		case 252 : printf("AXFR") ; break ;
		case 255 : printf("ANY") ; break ;
		default : printf("UNKNOW") ;
	}
}

int print_dns_rcode(unsigned char *dnshdr , int len)
{
	int num , n , x = 0 ;
	unsigned short int ptr ;
	if(Flag_dns_udp == 1)
	{
		ptr = DataOffset - sizeof(struct eth_header) - IPHeaderLength - UDPHeaderLength ;
	}
	else
	{
		ptr = DataOffset - sizeof(struct eth_header) - IPHeaderLength - TCPHeaderLength ;
	}
	A1 :
	if(dnshdr[ptr]>>6 == 0x3)
	{
		ptr = change_16(dnshdr[ptr],dnshdr[ptr+1]) ;
		ptr = ptr << 2 ;
		ptr = ptr >> 2 ;
		A2 :
		num = dnshdr[ptr] ;
		for(n=0;n<num;n++)
		{
			ptr++ ;
			printf("%c",dnshdr[ptr]) ;
		}
		ptr++ ;
		printf(".") ;
		if(dnshdr[ptr]>>6 == 0x3)
		{
			goto A1 ;
		}
		if(dnshdr[ptr]!=0)
		{
			goto A2 ;
		}
		else
		{
			x += 2 ;
		}
	}
	else if(dnshdr[ptr] == 0x00)
	{
		x++ ;
		printf(".") ;
	}
	else
	{
		A3 :
		num = dnshdr[ptr] ;
		for(n=0;n<num;n++)
		{
			ptr++ ;
			x++ ;
			printf("%c",dnshdr[ptr]) ;
		}
		ptr++ ;
		x++ ;
		printf(".") ;
		if((dnshdr[ptr]>>6 == 0x3) && (x<len))
		{
			goto A1 ;
		}
		if(dnshdr[ptr]!=0)
		{
			goto A3 ;
		}
		else
		{
			x++ ;
		}
	}
	return x ;
}

void print_dns_answer(void)
{
	unsigned short int type ;
	unsigned int ttl ;
	int len ;
	int num ;
	int tmp ;
	printf("\t") ;
	DataOffset += print_dns_rcode((char*)dnshdr , 256) ;
	printf("\tIN\t") ;
	type = change_16(buf[DataOffset],buf[DataOffset+1]) ;
	print_dns_type(type) ;
	DataOffset += 2 ;
	if(change_16(buf[DataOffset],buf[DataOffset+1])==1)
	{
		printf("\tInternet\t") ;
	}
	DataOffset += 2 ;
	ttl = change_32(buf[DataOffset],buf[DataOffset+1],buf[DataOffset+2],buf[DataOffset+3]) ;
	DataOffset += 4 ;
	len = change_16(buf[DataOffset],buf[DataOffset+1]) ;
	DataOffset += 2 ;
	if((len==4)&&(type==1))
	{
		printf("\t%d.%d.%d.%d",buf[DataOffset],buf[DataOffset+1],buf[DataOffset+2],buf[DataOffset+3]) ;
		DataOffset += len ;
	}
	else if((len==16)&&(type==28))
	{
		printf("\t") ;
		print_address_ipv6(&buf[DataOffset]) ;
		DataOffset += len ;
	}
	else
	{
		print_dns_rcode((char *)dnshdr , len) ;
		DataOffset += len ;
	}
	printf("\tTTL : %d\n",ttl);
}

void print_dns_details(void)
{
	int n ; 
	int num ;
	int len ;
	unsigned int type ;

	unsigned short int Questions = change_16(dnshdr->Questions[0],dnshdr->Questions[1]) ;
	unsigned short int Answer = change_16(dnshdr->Answer[0],dnshdr->Answer[1]) ;
	unsigned short int Authority = change_16(dnshdr->Authority[0],dnshdr->Authority[1]) ;
	unsigned short int Additional = change_16(dnshdr->Additional[0],dnshdr->Additional[1]) ;
	printf("\n") ;
	if (v == 1)
	{
		printf("ID : %d\n",change_16(dnshdr->id[0],dnshdr->id[1])) ;
		printf("Flags QR : %d\n",dnshdr->QR) ;
		printf("Flags opcode : %d\n",dnshdr->opcode) ;
		printf("Flags AA : %d\n",dnshdr->AA) ;
		printf("Flags TC : %d\n",dnshdr->TC) ;
		printf("Flags RD : %d\n",dnshdr->RD) ;
		printf("Flags RA : %d\n",dnshdr->RA) ;
		printf("Flags rcode : %d\n",dnshdr->rcode) ;
		printf("Questions : %d\n",Questions) ;
		printf("Answer : %d\n",Answer) ;
		printf("Authority : %d\n",Authority) ;
		printf("Additional : %d\n",Additional) ;
	}
	if(Questions>0)
	{
		printf("QUESTION SECTION : \n\t") ;
		for(n=0;n<Questions;n++)
		{
			DataOffset += print_dns_rcode((char *)dnshdr , 256) ;
			printf("\tIN\t") ;
			type = change_16(buf[DataOffset],buf[DataOffset+1]) ;
			print_dns_type(type) ;
			printf("\t") ;
			DataOffset += 2 ;
			if(change_16(buf[DataOffset],buf[DataOffset+1])==1)
			{
				printf("Internet\n") ;
			}
			DataOffset += 2 ;
			printf("\n") ;
		}
	}
	if(Answer>0)
	{
		printf("ANSWER SECTION : \n") ;
		for(n=0;n<Answer;n++)
		{
			print_dns_answer() ;
		}
	}
	if(Authority>0)
	{
		printf("AUTHORITY SECTION :\n") ;
		for(n=0;n<Authority;n++)
		{
			print_dns_answer() ;
		}
	}
	if(Additional>0)
	{
		printf("ADDITIONAL SECTION :\n") ;
		for(n=0;n<Additional;n++)
		{
			print_dns_answer() ;
		}
	}
	//Flag_dns = 0 ;
}

void dns(void)
{
	dnshdr = (struct dns_header *)&buf[DataOffset] ;
	DataOffset = DataOffset + sizeof(struct dns_header) ;
	//print_message() ;
}

void icmp(void)
{
	print_message() ;
}
void udp(void)
{
	int n ;
	SourcePort = change_16(udphdr->SourcePort[0],udphdr->SourcePort[1]) ;
	DestPort = change_16(udphdr->DestPort[0],udphdr->DestPort[1]) ;
	UDPHeaderLength = 8 ;
	DataOffset = sizeof(struct eth_header) + IPHeaderLength + UDPHeaderLength ;
	if(PORT_list != 0)
	{
		flag = 1 ;
		for(n=0;n<=PORT_list_num;n++)
		{
			if ((PORT_list[n] == SourcePort) || (PORT_list[n] == DestPort))
			{
				flag = 0 ;
			}
		}
		if (flag == 1)
		{
			return ;
		}
	}
	if(Flag_dns == 1)
	{
		Flag_dns_udp = 1 ;
		Flag_dns_tcp = 0 ;
		dns() ;
	}
	print_message() ;
}

void tcp(void)
{
	int n ;
	TCPHeaderLength = tcphdr->HeaderLength * 4 ;
	DataOffset = sizeof(struct eth_header) + IPHeaderLength + TCPHeaderLength ;
	SourcePort = change_16(tcphdr->SourcePort[0],tcphdr->SourcePort[1]) ;
	DestPort = change_16(tcphdr->DestPort[0],tcphdr->DestPort[1]) ;
	if(PORT_list != 0)
	{
		flag = 1 ;
		for(n=0;n<=PORT_list_num;n++)
		{
			if ((PORT_list[n] == SourcePort) || (PORT_list[n] == DestPort))
			{
				flag = 0 ;
			}
		}
		if (flag == 1)
		{
			return ;
		}
	}
	if(Flag_dns == 1)
	{
		Flag_dns_udp = 0 ;
		Flag_dns_tcp = 1 ;
		dns() ;
	}
	print_message() ;
}

void ipv6(void)
{
	int n , x ;
	if (IPv6_list != 0)
	{
		flag = 1 ;
		for(n=0;n<IPv6_list_num;n++)
		{
			for(x=0;x<16;x++)
			{
				if((ipv6hdr->SourceAddress[x] != IPv6_list[n][x]) || (ipv6hdr->DestAddress[x] != IPv6_list[n][x]))
				{
					break ;
				}
			}
			if(x==16)
			{
				flag = 0 ;
			}
		}
		if(flag == 1)
		{
			return ;
		}
	}
	if((ipv6hdr->NextHeader == 0x06) && (Flag_TCP == 1))
	{
		tcphdr = (struct tcp_header *)&buf[sizeof(struct eth_header) + IPHeaderLength] ;
		Flag_Protocol = 0x06 ;
		tcp() ;
	}
	else if((ipv6hdr->NextHeader == 0x11) && (Flag_UDP == 1) )
	{
		udphdr = (struct udp_header *)&buf[sizeof(struct eth_header)+ IPHeaderLength] ;
		Flag_Protocol = 0x11 ;
		udp() ;
	}
	else if((ipv6hdr->NextHeader == 0x3A) && (Flag_ICMP == 1))
	{
		icmphdr = (struct icmp_header *)&buf[sizeof(struct eth_header) + IPHeaderLength] ;
		Flag_Protocol = 0x3A ;
		icmp() ;
	}
	else
	{
		return ;
	}
}

void ipv4(void)
{
	int n ; 
	IPHeaderLength = iphdr->HeaderLength * 4 ;
	SourceAddress = change_32(iphdr->SourceAddress[0],iphdr->SourceAddress[1],iphdr->SourceAddress[2],iphdr->SourceAddress[3]);
	DestAddress = change_32(iphdr->DestAddress[0],iphdr->DestAddress[1],iphdr->DestAddress[2],iphdr->DestAddress[3]) ;
	if (IPv4_list != 0)
	{
		flag = 1 ;
		for(n=0;n<=IPv4_list_num;n++)
		{
			if ((SourceAddress == IPv4_list[n])||(DestAddress == IPv4_list[n]))
			{
				flag = 0 ;
			}
		}
		if(flag == 1)
		{
			return ;
		}
	}
	if((iphdr->Protocol == 0x06) && (Flag_TCP == 1))
	{
		tcphdr = (struct tcp_header *)&buf[sizeof(struct eth_header) + IPHeaderLength] ;
		Flag_Protocol = 0x06 ;
		tcp() ;
	}
	else if((iphdr->Protocol == 0x11) && (Flag_UDP == 1))
	{
		Flag_Protocol = 0x11 ;
		udphdr = (struct udp_header *)&buf[sizeof(struct eth_header)+ IPHeaderLength] ;
		udp() ;
	}
	else if((iphdr->Protocol == 0x01) && (Flag_ICMP == 1))
	{
		icmphdr = (struct icmp_header *)&buf[sizeof(struct eth_header) + IPHeaderLength] ;
		Flag_Protocol = 0x01 ;
		icmp() ;
	}
	else
	{
		return ;
	}
}

void arp(void)
{
	int n ;
	int SourceAddress = change_32(arphdr->SourceAddress[0],arphdr->SourceAddress[1],arphdr->SourceAddress[2],arphdr->SourceAddress[3]) ;
	int DestAddress = change_32(arphdr->DestAddress[0],arphdr->DestAddress[1],arphdr->DestAddress[2],arphdr->DestAddress[3]) ;
	if (IPv4_list != 0)
	{
		flag = 1 ;
		for(n=0;n<=IPv4_list_num;n++)
		{
			if ((SourceAddress == IPv4_list[n])||(DestAddress == IPv4_list[n]))
			{
				flag = 0 ;
			}
		}
		if(flag == 1)
		{
			return ;
		}
	}
	DataOffset = sizeof(struct eth_header) + sizeof(struct arp_header);
	print_message() ;
}

void print_arp_details(void)
{
	if ( v == 1 )
	{
		printf("ARP Hardware Type : 0x%02X%02X\n",arphdr->HardwareType[0],arphdr->HardwareType[1]);
		printf("ARP Protocol : 0x%02X%02X\n",arphdr->Protocol[0],arphdr->Protocol[1]);
		printf("ARP MAC LEN : %d\n",arphdr->MAC_LEN);
		printf("ARP IP Address LEN : %d\n",arphdr->IPADDRESS_LEN);
		printf("ARP Operation : 0x%02X%02X\n",arphdr->Operation[0],arphdr->Operation[1]);
		printf("ARP Source MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n",arphdr->SourceMAC[0],arphdr->SourceMAC[1],arphdr->SourceMAC[2],arphdr->SourceMAC[3],arphdr->SourceMAC[4],arphdr->SourceMAC[5]) ;
		printf("ARP Source Address : %d.%d.%d.%d\n",arphdr->SourceAddress[0],arphdr->SourceAddress[1],arphdr->SourceAddress[2],arphdr->SourceAddress[3]) ;
		printf("ARP Dest   MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n",arphdr->DestMAC[0],arphdr->DestMAC[1],arphdr->DestMAC[2],arphdr->DestMAC[3],arphdr->DestMAC[4],arphdr->DestMAC[5]) ;
		printf("ARP Dest   Address : %d.%d.%d.%d\n",arphdr->DestAddress[0],arphdr->DestAddress[1],arphdr->DestAddress[2],arphdr->DestAddress[3]) ;
	}
	if((arphdr->Protocol[0]==0x08) && (arphdr->Protocol[1]==0x00) && (arphdr->MAC_LEN==0x06) && (arphdr->IPADDRESS_LEN==0x04))
	{
		if ( arphdr->Operation[1] == 0x01)
		{
			printf("request  : %d.%d.%d.%-3d --> ",arphdr->SourceAddress[0],arphdr->SourceAddress[1],arphdr->SourceAddress[2],arphdr->SourceAddress[3]) ;
			printf("who is %d.%d.%d.%d\n",arphdr->DestAddress[0],arphdr->DestAddress[1],arphdr->DestAddress[2],arphdr->DestAddress[3]) ;
		}
		else if(arphdr->Operation[1] == 0x02)
		{
			printf("response : %d.%d.%d.%-3d --> ",arphdr->SourceAddress[0],arphdr->SourceAddress[1],arphdr->SourceAddress[2],arphdr->SourceAddress[3]) ;
			printf("mac is %02X:%02X:%02X:%02X:%02X:%02X\n",arphdr->SourceMAC[0],arphdr->SourceMAC[1],arphdr->SourceMAC[2],arphdr->SourceMAC[3],arphdr->SourceMAC[4],arphdr->SourceMAC[5]) ;
		}
	}
}

void print_all_hex(void)
{
	int n , y ;
	for(n=0;n<recv_len;n+=16)
	{
		for(y=0;y<8;y++)
		{
			if(n+y<recv_len)
			{
				printf("%02X ",buf[n+y]) ;
			}
			else
			{
				printf("   ") ;
			}
		}
		printf(" ") ;
		for(y=8;y<16;y++)
		{
			if(n+y<recv_len)
			{
				printf("%02X ",buf[n+y]) ;
			}
			else
			{
				printf("   ") ;
			}
		}

		printf("   ") ;
		for(y=0;y<16;y++)
		{
			if(n+y<recv_len)
			{
				if (((buf[n+y] >= 32) && (buf[n+y] <= 126)))
				{
					printf("%c",buf[n+y]) ;
				}
				else if (buf[n+y] == '\n')
				{
					printf("\033[31mn\033[0m") ;
				}
				else if (buf[n+y] == '\r')
				{
					printf("\033[31mr\033[0m") ;
				}
				else if (buf[n+y] == '\t')
				{
					printf("\033[31mt\033[0m") ;
				}
				else
				{
					printf(".") ;
				}
			}
			else
			{
				printf("   ") ;
			}
		}
		printf("\n");
	}
}

void print_data_char(void)
{
	int n ;
	if(DataOffset < recv_len)
	{
		printf("\n----------------------------------------------DATA-CHAR---------------------------------------------------\n") ;
		for(n=DataOffset ; n < recv_len ; n++ )
		{
			printf("%c",buf[n]) ;
		}
		if(buf[recv_len-1] != '\n')
		{
			printf("\n") ;
		}
		printf("----------------------------------------------------------------------------------------------------------\n") ;
	}
}

void print_time(void)
{
	FILE *file;
	char ch ;
	file = popen("date +\"%Y-%m-%d %T\"","r") ;
	while(1)
	{
		ch = fgetc(file) ;
		if(feof(file) != 0)
		{
			break ;
		}
		printf("%c",ch) ;
	}
}

void print_message(void)
{
	received_num ++ ;
	print_time();
	if( v == 1 )
	{
		print_eth_details();
		if(Flag_IP_Version == 0x4)
		{
			print_iph_details();
		}
		else if (Flag_IP_Version == 0x6)
		{
			print_iph_details_IPv6() ;
		}
		else if (Flag_arp == 1)
		{
			print_arp_details();
		}
		if(Flag_Protocol == 0x06)
		{
			print_tcp_details();
		}
		else if(Flag_Protocol == 0x11)
		{
			print_udp_details();
		}
		else if((Flag_Protocol == 0x3A) || (Flag_Protocol == 0x01))
		{
			print_icmp_details() ;
		}
		if (Flag_dns == 1)
		{
			print_dns_details() ;
		}
	}
	else
	{
		if(Flag_IP_Version == 0x4)
		{
			print_ip_address();
		}
		else if(Flag_IP_Version == 0x6)
		{
			print_ip_address_IPv6() ;
		}
		else if(Flag_arp == 1)
		{
			print_arp_details() ;
		}
		if((Flag_Protocol == 0x06) || (Flag_Protocol == 0x11))
		{
			print_port_tcp_or_udp();
		}
		else if((Flag_Protocol == 0x3A) || (Flag_Protocol == 0x01))
		{
			print_icmp_details() ;
		}
		if(Flag_dns == 1)
		{
			print_dns_details() ;
		}
	}
	if(data_char == 1)
	{
		print_data_char();
	}
	if(all_hex == 1)
	{
		print_all_hex();
	}
	printf("\n**********************************************************************************************************\n") ;
}

int check_argv(int argc , char **argv)
{
	int num , flag_protocol ; 
	Flag_arp = 0 ;
	Flag_IPv6 = 0 ;
	Flag_IPv4 = 0 ;
	Flag_TCP = 0 ;
	Flag_UDP = 0 ;
	Flag_ICMP = 0 ;
	Flag_dns = 0 ;
	/* check protocol */
	for(flag_protocol=0,num=1;num<argc;num++)
	{
		if((strcmp(argv[num],"ipv4")==0) || (strcmp(argv[num],"-4")==0))
		{
			Flag_IPv4 = 1 ;
			Flag_IPv6 = 0 ;
			Flag_arp = 0 ;
			flag_protocol ++ ;
		}
		if((strcmp(argv[num],"ipv6")==0) || (strcmp(argv[num],"-6")==0))
		{
			Flag_IPv4 = 0 ;
			Flag_IPv6 = 1 ;
			Flag_arp = 0 ;
			flag_protocol ++ ;
		}
		if(strcmp(argv[num],"arp")==0)
		{
			Flag_IPv4 = 0 ;
			Flag_IPv6 = 0 ;
			Flag_arp = 1 ;
			flag_protocol ++ ;
		}
	}
	if(flag_protocol > 1)
	{
		printf("protocol error\n") ;
		print_usage() ;
		return 1 ;
	}
	for(flag_protocol=0,num=1;num<argc;num++)
	{
		if(strcmp(argv[num],"tcp")==0)
		{
			Flag_TCP = 1 ;
			Flag_UDP = 0 ;
			Flag_ICMP = 0 ;
			flag_protocol ++ ;
		}
		if(strcmp(argv[num],"udp")==0)
		{
			Flag_TCP = 0 ;
			Flag_UDP = 1 ;
			Flag_ICMP = 0 ;
			flag_protocol ++ ;
		}
		if(strcmp(argv[num],"icmp")==0)
		{
			Flag_TCP = 0 ;
			Flag_UDP = 0 ;
			Flag_ICMP = 1 ;
			flag_protocol ++ ;
		}
	}
	if (flag_protocol>1)
	{
		printf("protocol error\n") ;
		print_usage() ;
		return 1 ;
	}
	if((Flag_arp==1)&&(Flag_IPv4==1||Flag_IPv6==1))
	{
		printf("protocol error\n") ;
		print_usage() ;
		return 1 ;
	}
	if((Flag_arp==1)&&((Flag_TCP==1)||(Flag_UDP==1)||(Flag_ICMP==1)))
	{
		printf("protocol error\n") ;
		print_usage() ;
		return 1 ;
	}
	if ( ((Flag_TCP==1)||(Flag_UDP==1)||(Flag_ICMP==1)) && ((Flag_IPv4==0)&&(Flag_IPv6==0)) )
	{
		Flag_IPv4 = 1;
		Flag_IPv6 = 1;
	}

	/* check argv */
	for(num=1;num<argc;num++)
	{
		if(strcmp(argv[num],"host")==0)
		{
			num++ ;
			if(num >= argc)
			{
				print_usage() ;
				return 1 ;
			}
			if(check_argv_host(argv[num])==0)
			{
				continue ;
			}
			else
			{
				printf("IP Error\n") ;
				print_usage() ;
				return 1 ;
			}
		}
		else if(strcmp(argv[num],"port")==0)
		{
			if(Flag_arp==1)
			{
				printf("protocol error\n") ;
				print_usage() ;
				return 1 ;
			}
			if((Flag_IPv4==0)&&(Flag_IPv6==0))
			{
				Flag_IPv4 = 1 ;
				Flag_IPv6 = 1 ;
			}
			if((Flag_TCP==0)&&(Flag_UDP==0))
			{
				Flag_TCP = 1 ;
				Flag_UDP = 1 ;
			}
			num++ ;
			if(num >= argc)
			{
				print_usage() ;
				return 1 ;
			}
			if(check_argv_port(argv[num])==0)
			{
				continue ;
			}
			else
			{
				printf("Port Error\n") ;
				print_usage() ;
				return 1 ;
			}
		}
		else if(strcmp(argv[num],"-v")==0)
		{
			v = 1 ;
		}
		else if(strcmp(argv[num],"--print-all-hex")==0)
		{
			all_hex = 1 ;
		}
		else if(strcmp(argv[num],"--print-data-char")==0)
		{
			data_char = 1 ;
		}
		else if(strcmp(argv[num],"arp") == 0)
		{
			continue ;
		}
		else if((strcmp(argv[num],"ipv4")==0) || (strcmp(argv[num],"-4")==0))
		{
			if((Flag_TCP==0)&&(Flag_UDP==0)&&(Flag_ICMP==0))
			{
				Flag_TCP = 1 ;
				Flag_UDP = 1 ;
				Flag_ICMP = 1 ;
			}
		}
		else if((strcmp(argv[num],"ipv6")==0) || (strcmp(argv[num],"-6")==0))
		{
			if((Flag_TCP==0)&&(Flag_UDP==0)&&(Flag_ICMP==0))
			{
				Flag_TCP = 1 ;
				Flag_UDP = 1 ;
				Flag_ICMP = 1 ;
			}
		}
		else if(strcmp(argv[num],"tcp")==0)
		{
			continue ;
		}
		else if(strcmp(argv[num],"udp")==0)
		{
			continue ;
		}
		else if(strcmp(argv[num],"icmp")==0)
		{
			continue ;
		}
		else if(strcmp(argv[num],"dns")==0)
		{
			continue ;
		}
		else if(strcmp(argv[num],"--help")==0)
		{
			print_usage() ;
			return 1 ;
		}
		else if(strcmp(argv[num],"--print-tcpdump-flag")==0)
		{
			Flag_tcpdump = 1 ;
		}
		else
		{
			printf("unknow : %s\n",argv[num]) ;
			print_usage() ;
			return 1 ;
		}
	}

	for(num=1;num<argc;num++)
	{
		if(strcmp(argv[num],"dns")==0)
		{
			if(PORT_list == 0)
			{
				printf("pls input a port\n") ;
				print_usage() ;
				return 1 ;
			}
			if(Flag_arp == 1)
			{
				print_usage() ;
			}
			if(Flag_ICMP == 1)
			{
				print_usage() ;
			}
			if((Flag_IPv4==0)&&(Flag_IPv6==0))
			{
				Flag_IPv4 = 1 ;
				Flag_IPv6 = 1 ;
			}
			if((Flag_TCP==0)&&(Flag_UDP==0))
			{
				Flag_TCP = 1 ;
				Flag_UDP = 1 ;
			}
			Flag_dns = 1 ;
		}
	}

	if(Flag_tcpdump == 1)
	{
		printf("Flag arp  : %d\n",Flag_arp) ;
		printf("Flag IPv4 : %d\n",Flag_IPv4) ;
		printf("Flag IPv6 : %d\n",Flag_IPv6) ;
		printf("Flag TCP  : %d\n",Flag_TCP) ;
		printf("Flag UDP  : %d\n",Flag_UDP) ;
		printf("Flag ICMP : %d\n",Flag_ICMP) ;
		printf("Flag dns  : %d\n",Flag_dns) ;
		sleep(3) ;
	}

	return 0 ;
}

int check_argv_host(char *host)
{
	int host_quantity ;
	int num ;
	int flag ;
	char tmp[100] ;
	int tmp_num ;
	int ipv4_list_num ;
	int ipv6_list_num ;
	bzero(tmp,100) ;
	for(num=0;host[num]!=0;num++)
	{
		if(host[num]==',')
		{
			host_quantity++ ;
		}
	}
	host_quantity++ ;
	if(Flag_IPv4 == 1 || Flag_arp == 1)
	{
		IPv4_list = (unsigned int *)malloc(sizeof(int)*host_quantity) ;
	}
	if(Flag_IPv6 == 1)
	{
		IPv6_list = (unsigned char **)malloc(sizeof(char *)*host_quantity) ;
		for(num=0;num<host_quantity;num++)
		{
			IPv6_list[num] = (unsigned char *)malloc(100) ;
		}
	}
	flag = 0 ;
	tmp_num = 0 ;
	ipv4_list_num = 0 ;
	ipv6_list_num = 0 ;
	for(num=0;;num++)
	{
		if((host[num]==',') || (host[num]==0))
		{
			tmp[tmp_num] = 0 ;
			if((Flag_IPv4 == 1) && (Flag_IPv6 == 1))
			{
				IPv4_list[ipv4_list_num] = htonl(inet_addr(tmp)) ;
				if(IPv4_list[ipv4_list_num] == -1)
				{
					if(inet_pton(AF_INET6,tmp,IPv6_list[ipv6_list_num]) <= 0 )
					{
						return 1 ;
					}
					else
					{
						ipv6_list_num ++ ;
					}
				}
				else
				{
					ipv4_list_num ++ ;
				}
			}
			else if((Flag_IPv4 == 1 || Flag_arp == 1) && (Flag_IPv6 == 0))
			{
				IPv4_list[ipv4_list_num] = htonl(inet_addr(tmp)) ;
				if(IPv4_list[ipv4_list_num] == -1)
				{
						return 1 ;
				}
				ipv4_list_num ++ ;
			}
			else if((Flag_IPv4 == 0) && (Flag_IPv6 == 1))
			{
				if(inet_pton(AF_INET6,tmp,IPv6_list[ipv6_list_num]) <= 0)
				{
					return 1 ;
				}
				ipv6_list_num ++ ;
			}
			if(host[num]==0)
			{
				break ;
			}
			num++ ;
			tmp_num = 0 ;
		}
		tmp[tmp_num] = host[num] ;
		tmp_num++ ;
	}
	IPv4_list_num = ipv4_list_num ;
	IPv6_list_num = ipv6_list_num ;
	return 0 ;
}

int check_argv_port(char *port)
{
	long long int tmp = 0 ;
	int port_num = 0 ;
	int port_quantity = 0 ;
	int num ;
	for(num=0;port[num]!=0;num++)
	{
		if(port[num] == ',')
		{
			port_quantity ++ ;
		}
	}
	port_quantity ++ ;
	PORT_list_num = port_quantity ;
	PORT_list = (unsigned int *)malloc(sizeof(int)*port_quantity) ;
	for(num=0;;num++)
	{
		if((port[num] == ',') || (port[num] == 0))
		{
			if((tmp<0)||(tmp>65535))
			{
				return 1 ;
			}
			PORT_list[port_num] = tmp ; 
			port_num ++ ;
			tmp = 0 ;
			if(port[num] == 0)
			{
				break ;
			}
			else
			{
				continue ;
			}
		}
		tmp *= 10 ;
		tmp += port[num] - '0' ;
	}
	return 0 ;
}

void print_usage(void)
{
	printf("Version : 0.5\n") ;
	printf("Usage : tcpdump [host <ip address>] [port <port number>]\n") ;
	printf("                [arp] [ipv4/ipv6] [tcp/udp/icmp] [dns] [-v]\n") ;
	printf("                [--print-all-hex] [--print-data-char]\n") ;
	printf("		[--print-tcpdump-flag]\n") ;
	printf("Example : tcpdump host 127.0.0.1 port 80 tcp -v --print-all-hex\n") ;
	printf("Example : tcpdump host 127.0.0.1,::1 port 80,8080\n") ;
	printf("Example : tcpdump tcp port 80\n") ;
	printf("Example : tcpdump udp port 53\n") ;
	printf("Example : arp host 192.168.1.1\n") ;
}
