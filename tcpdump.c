/* tcpdump */
# include <stdio.h>
# include <sys/socket.h>
# include <linux/if_ether.h>
# include <malloc.h>
# include <string.h>
# include <arpa/inet.h>

long long int string_to_int(char *string) ;
extern int change_16(char ah,char al) ;
extern int change_32(char c_32 ,char c_24 , char c_16 , char c_8) ;
extern char bit(char ch , char num) ;
void print_binary(char num) ;

int main(int argc , char **argv)
{
	if(argc < 3)
	{
		printf("%s [ IP ] [PORT] [show_ip show_port show_data_Bin show_data_Hex show_data_char show_all_Hex ] [ -v ]\n" , argv[0])  ;
		return 1 ;
	}

	unsigned long int IP = htonl(inet_addr(argv[1])) ;
	int PORT = (int)string_to_int(argv[2]) ;

	int show_ip = 0 ;
	int show_port = 0 ;
	int show_data_char = 0 ;
	int show_data_Bin = 0 ;
	int show_data_Hex = 0 ;
	int show_all_Hex = 0 ;
	int show_v = 0 ;

	int num = 3 ;
	for( ; num<argc ; num++)
	{
		if ( strcmp(argv[num],"show_ip") == 0 )
		{
			show_ip = 1 ;
		}
		else if ( strcmp(argv[num],"show_port") == 0 )
		{
			show_port = 1 ;
		}
		else if ( strcmp(argv[num],"show_data_Bin") == 0 )
		{
			show_data_Bin = 1 ;
		}
		else if ( strcmp(argv[num],"show_data_Hex") == 0 )
		{
			show_data_Hex = 1 ;
		}
		else if ( strcmp(argv[num],"show_data_char") == 0 )
		{
			show_data_char = 1 ;
		}
		else if ( strcmp(argv[num],"show_all_Hex") == 0 )
		{
			show_all_Hex = 1 ;
		}
		else if ( strcmp(argv[num],"-v") == 0 )
		{
			show_v = 1 ;
		}
		else
		{
			printf("unknow %s\n",argv[num]) ;
			printf("%s [ IP ] [PORT] [show_ip show_port show_data_Bin show_data_Hex show_data_char] [ -v ]\n" , argv[0])  ;
			return 1 ;
		}
	}


	char *buf = (char *)malloc(1500) ;
	int buf_len = 1500 ;
	int sockfd ;
	sockfd = socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL)) ;
	if (sockfd == -1)
	{
		printf("socket faild\n") ;
		return 1 ;
	}

	unsigned int ethhdr_protocol ;
	unsigned char iphdr_protocol ;
	unsigned char version ;
	unsigned char *source_mac = (char *)malloc(7) ;
	unsigned char *dest_mac = (char *)malloc(7) ;
	unsigned char *source_ip = (char *)malloc(5) ;
	unsigned char *dest_ip = (char *)malloc(5) ;
	unsigned int SIP ;
	unsigned int DIP ;
	int source_port ;
	int dest_port ;

	unsigned int recv_len = -1 ;
	unsigned int ip_len = -1 ;
	unsigned long int tmp ;
	unsigned int tcp_offset = -1 ;
	unsigned int tcp_len = -1 ;
	unsigned char urg , ack , psh , rst , syn , fin ;
	unsigned int data_offset = -1 ;
	int n ;
	int y ;


	while(1)
	{
		recv_len = recvfrom(sockfd,buf,buf_len,0,NULL,NULL) ;
		if(recv_len == -1)
		{
			printf("recvfrom faild\n") ;
			return 1 ;
		}


		/* ###################################################################################################################### */
		/* 获取ethhdr协议号 */
		ethhdr_protocol = change_16(buf[12],buf[13]) ;

		/* 获取iphdr协议号 */
		iphdr_protocol = (unsigned char)buf[23] ;

		/* 获取version */
		version = (unsigned char)((buf[14])>>4) ;

		/* 获取MAC地址 */
		for(n=0;n<6;n++)
		{
			dest_mac[n] = buf[n] ;
		}
		source_mac[n] = '\0' ;
		for(n=6;n<12;n++)
		{
			source_mac[n-6] = buf[n] ;
		}
		source_mac[n-6] = '\0' ;

		/* 获取IP地址 */
		for(n=26;n<30;n++)
		{
			source_ip[n-26] = buf[n] ;
		}
		source_ip[n-26] = '\0' ;
		for(n=30;n<34;n++)
		{
			dest_ip[n-30] = buf[n] ;
		}
		dest_ip[n-30] = '\0' ;

		/* 转换IP地址 */
		SIP = change_32(source_ip[0] , source_ip[1] , source_ip[2] , source_ip[3]) ;
		DIP = change_32(dest_ip[0] , dest_ip[1] , dest_ip[2] , dest_ip[3]) ;

		/* 获取ip层长度 */
		ip_len = (unsigned char)((buf[14])<<4) ;
		ip_len = (unsigned char)(ip_len >> 4) ;
		ip_len *= 4 ;

		/* 获取tcp层偏移位置 */
		tcp_offset = 14 + ip_len ;

		/* 获取源目的端口 */
		source_port = change_16(buf[tcp_offset] , buf[tcp_offset+1]) ;
		tcp_offset += 2 ;
		dest_port = change_16(buf[tcp_offset] , buf[tcp_offset+1]) ;

		/* ####################################################################################################################################### */

		if(IP != 0)
		{
			if ( ( IP != SIP ) && (IP != DIP) )
			{
				continue ;
			}
		}


		if(PORT != 0)
		{
			if( (source_port != PORT) && (dest_port != PORT) )
			{
				continue ;
			}
		}

		/* ####################################################################################################################################### */
		//printf("- - - - - - - ethhdr - - - - - - -\n\n") ;
		if (show_v == 1)
		{
			printf("ethhdr protocol 0x%04X\t" , ethhdr_protocol) ;
			if(ethhdr_protocol == 0x0800)
			{
				printf("IP 报文 协议号") ;
				printf("\n") ;
			}
			else
			{
				printf("\n") ;
				continue ;
			}
		}

		if(show_v == 1)
		{
			printf("Dest MAC addr %02X:%02X:%02X:%02X:%02X:%02X\n",dest_mac[0] , dest_mac[1] , dest_mac[2] , dest_mac[3] ,dest_mac[4] , dest_mac[5]) ;
			printf("Source MAC addr %02X:%02X:%02X:%02X:%02X:%02X\n", source_mac[0] , source_mac[1] , source_mac[2] , source_mac[3] , source_mac[4] , source_mac[5]) ;
		}

		//printf("\n\n- - - - - - - iphdr - - - - - - -\n\n") ;

		if(version != 4)
		{
			continue ;
		}

		if(show_v == 1)
		{
			printf("version IPV%X\n",(char)version) ;
			printf("iphdr len %d\tIP 报文长度\n" , ip_len  ) ;
			printf("iphdr tos %d\n" , (unsigned char)buf[15] ) ;
			tmp = change_16(buf[16],buf[17]) ;
			printf("iphdr len + tcphdr len + data len =  %u\tIP报文+TCP报文+数据段 总长度\n" , tmp) ;
			tmp = change_16(buf[18] , buf[19]) ;
			printf("iphdr id %u\n" , tmp ) ;
			tmp = change_16(buf[20] , buf[21]) ;
			printf("iphdr off %u\n" , tmp ) ;
			printf("iphdr ttl %d\n" , (unsigned char)buf[22] ) ;
		}

		if(iphdr_protocol != 0x6)
		{
			continue ;
		}

		if(show_v == 1)
		{
			printf("iphdr protocol 0x%02X\ttcp 报文 协议号\n",(char)iphdr_protocol) ;
			tmp = change_16(buf[24],buf[25]) ;
			printf("iphdr check sum %u\n" , tmp) ;	
		}

		if(show_ip == 1)
		{
			printf("Source IP %d.%d.%d.%d\n" , source_ip[0] , source_ip[1] , source_ip[2] , source_ip[3]) ;
			printf("Dest IP %d.%d.%d.%d\n" , dest_ip[0] , dest_ip[1] , dest_ip[2] , dest_ip[3]) ;
		}

		tcp_offset = 14 + ip_len ;
		//printf("\n\n- - - - - - - tcphdr - - - - - - -\n\n") ;
		if(show_port == 1)
		{
			printf("Source port %u\n",source_port) ;
			printf("Dest port %u\n",dest_port) ;
		}
		tcp_offset += 4 ;
		
		if(show_v == 1)
		{
			tmp = change_32(buf[tcp_offset] , buf[tcp_offset+1] , buf[tcp_offset+2] , buf[tcp_offset+3] ) ;
			printf("Seq %u\n" , (int)tmp) ;
		}
		tcp_offset += 4 ;

		if(show_v == 1)
		{
			tmp = change_32(buf[tcp_offset] , buf[tcp_offset+1] , buf[tcp_offset+2] , buf[tcp_offset+3] ) ;
			printf("Ack Seq %u\n" , (int)tmp ) ;
		}
		tcp_offset += 4 ;
		
		tcp_len = (unsigned char)buf[tcp_offset] >> 4 ;
		tcp_len *= 4 ;

		if(show_v == 1)
		{
			printf("tcp len %d\tTCP 报文 长度\n",tcp_len) ;
		}
		tcp_offset += 1 ;

		if(show_v == 1)
		{
			urg = bit(buf[tcp_offset] , 6) ;
			printf("URG = %d\n" , urg ) ;

			ack = bit(buf[tcp_offset] , 5) ;
			printf("ACK = %d\n" , ack) ;

			psh = bit(buf[tcp_offset] , 4) ;
			printf("PSH = %d\n" , psh ) ;

			rst = bit(buf[tcp_offset] , 3) ;
			printf("RST = %d\n" , rst) ;

			syn = bit(buf[tcp_offset] , 2) ;
			printf("SYN = %d\n" , syn) ;

			fin = bit(buf[tcp_offset] , 1) ;
			printf("FIN = %d\n" , fin) ;
		}

		tcp_offset += 1 ;
		
		if(show_v == 1)
		{
			tmp = change_16(buf[tcp_offset] , buf[tcp_offset+1]) ;
			printf("win %u\n",tmp) ;
		}
		tcp_offset += 2 ;

		if(show_v == 1)
		{
			tmp = change_16(buf[tcp_offset] , buf[tcp_offset+1]) ;
			printf("tcp check sum %u\n" , tmp ) ;
		}
		tcp_offset += 2 ;

		if(show_v == 1)
		{
			tmp = change_16(buf[tcp_offset] , buf[tcp_offset+1]) ;
			printf("urg_ptr %u\n" , tmp) ;
		}

		data_offset = 14 + ip_len + tcp_len ;

		if(show_data_Bin == 1)
		{
			y = 0 ;
			for(n=data_offset ; n<recv_len ; n++)
			{
				print_binary(buf[n]) ;
				printf(" ") ;
				y++ ;
				if(y % 16 == 0)
				{
					printf("\n") ;
				}
			}
			printf("\n");
		}

		if(show_data_Hex == 1)
		{
			//printf("\n\n- - - - - - - - - data bin - - - - - - - - -\n\n") ;
			y = 0 ;
			for(n=data_offset;n<recv_len;n++)
			{
				printf("%02X ",(unsigned char)(buf[n])) ;
				y++ ;
				if(y % 16 == 0)
				{
					printf("\n") ;
				}
			}
			printf("\n") ;
		}

		if(show_data_char == 1)
		{
			//printf("\n\n- - - - - - - - - data char - - - - - - - - -\n\n") ;
			printf("-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n") ;
			for(n=data_offset ; n < recv_len ; n++ )
			{
				if ((buf[n] == 0) || ((buf[n] >= 8) && (buf[n] <= 13)) || ((buf[n] >= 32) && (buf[n] <= 127)))
				{
					printf("%c",buf[n]) ;
				}
				else
				{
					printf("?") ;
				}
			}
			printf("\n-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n") ;
		}

		if(show_all_Hex == 1)
		{
			y = 0 ;
			for(n=0;n<recv_len;n++)
			{
				printf("%02X ",(unsigned char)(buf[n])) ;
				y++ ;
				if(y % 8 == 0)	
				{
					printf(" ") ;
				}
				if(y % 16 == 0)
				{
					printf("\n") ;
				}
			}
		}
		printf("\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n") ;

		bzero(buf,1500) ;
	}

	free(buf) ;
	return 0 ;
}

long long int string_to_int(char *string)
{
	int len = strlen(string) ;
	long long int x = 0 ;
	int y ;
	for(y=0;y<len;y++)
	{
		x *= 10 ;
		x += string[y] - '0' ;
	}
	return x ;
}

void print_binary(char num)
{
	int x ;
	for(x=8;x>0;x--)
	{
		printf("%X" , (unsigned char)bit(num , x) ) ;
	}
}
