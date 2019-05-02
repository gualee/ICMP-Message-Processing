#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>

#define PACKET_SIZE 4096

char send_buffer[PACKET_SIZE];
char recv_buffer[PACKET_SIZE];
char *addr[0];
int send_number = 0, recv_number = 0;
int sd;
struct sockaddr_in recv_addr;
struct sockaddr_in from;
pid_t pid;

void send_packet(void);
void recv_packet(void);
int icmp_packet(int pack_number);
int icmp_unpacket(char *buffer, int length);
unsigned short cal_checksum(unsigned short *address,int length);

int main(int argc, char *argv[]){
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0;
    addr[0] = argv[1];
    
    if(argc < 2){
        printf("usage:%s hostname/IP address\n",argv[0]);
        exit(1);
    }

    if((sd = socket(PF_INET,SOCK_RAW,1)) < 0){
        perror("socket error");
        exit(1);
    }

    setuid(getuid());
    bzero(&recv_addr,sizeof(recv_addr));  
    recv_addr.sin_family = AF_INET;     

    if(inet_addr(argv[1]) == INADDR_NONE){
        if((host = gethostbyname(argv[1])) == NULL) {
            perror("gethostbyname error");
            exit(1);
        }
        memcpy((char *)&recv_addr.sin_addr,host->h_addr,host->h_length);
    }
    else{
        recv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    }
    pid = getpid();
      
    while(send_number < 10000){
        sleep(1);    
        send_packet();      
        recv_packet();      
    }

    close(sd);
    return 0;
}//end with main block

void send_packet(){
    int packetsize;
    if(send_number < 10000){
        send_number++;
	    packetsize = icmp_packet(send_number); 
        if(sendto(sd, send_buffer, packetsize, 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0){
            perror("sendto error");
        }
    }
}

int icmp_packet(int pack_number){
    int packsize = 56 + 8;
    double original_timestamp = 0;
    struct icmp *icmp_hdr = (struct icmp*)send_buffer;
    struct timeval tv1;
    icmp_hdr->icmp_type = ICMP_TIMESTAMP; //request and reply
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_id = pid;

    //packsize = datalength + 8;
    
    gettimeofday(&tv1,NULL);  
    original_timestamp = tv1.tv_sec + tv1.tv_usec;
    icmp_hdr->icmp_otime = original_timestamp;
    icmp_hdr->icmp_cksum = cal_checksum((unsigned short *)icmp_hdr,packsize);    
    
    printf("--------Send ICMP Packet\n");
    printf("icmp_type = %d,icmp_code = %d\n",icmp_hdr->icmp_type,icmp_hdr->icmp_code);
    printf("Original timestamp = %d\n",icmp_hdr->icmp_otime);
    printf("Receive timestamp = %d\n",icmp_hdr->icmp_rtime);
    printf("Transmit timestamp = %d\n",icmp_hdr->icmp_ttime);    
    printf("Final timestamp = 0\n");

    return packsize;
}

unsigned short cal_checksum(unsigned short *address, int length){
    int sum = 0;
    unsigned short *w = address;
    unsigned short check_sum = 0;
    while(length > 1){
        sum += *w++;
        length -= 2;
    }
    if(length == 1){
        *(unsigned char *)(&check_sum) = *(unsigned char *)w;
        sum += check_sum;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    check_sum = ~sum;  
    return check_sum;
}

void recv_packet(){
    struct icmp *icmp_hdr = (struct icmp*)send_buffer;
    int n,fromlen;
    extern int error; 
    fromlen = sizeof(from);
    if(recv_number < send_number){   
        if((n = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &fromlen)) < 0){
            perror("recvfrom error");
        }
    icmp_unpacket(recv_buffer, n);
    recv_number++;
    }
}

int icmp_unpacket(char *buf,int len){
    int i;
    int iphdrlen;       
    struct ip *ip;
    struct icmp *icmp_hdr;
    struct timeval back;
    double rtt, orig_time = 0 ,recv_time = 0, trans_time = 0, final_timestamp = 0;

    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl << 2;  
    icmp_hdr = (struct icmp *)(buf + iphdrlen); 
    len -= iphdrlen;    
   
    if(len < 8){
		printf("ICMP packet\'s length is less than 8\n");
        return -1;
    }

    if((icmp_hdr->icmp_type == ICMP_TIMESTAMPREPLY) && (icmp_hdr->icmp_id == pid)){
		gettimeofday(&back, NULL);  
		final_timestamp = back.tv_sec + back.tv_usec;
		orig_time = icmp_hdr->icmp_otime;
		recv_time = icmp_hdr->icmp_rtime;
		trans_time = icmp_hdr->icmp_ttime;
		rtt = abs(((final_timestamp - trans_time) + (recv_time - orig_time)) / 1000);

		printf("--------Receive ICMP Packet\n");
		printf("icmp_type = %d, icmp_code = %d\n",icmp_hdr->icmp_type, icmp_hdr->icmp_code);
		printf("Original timestamp = %d\n",icmp_hdr->icmp_otime);
		printf("Receive timestamp = %d\n",icmp_hdr->icmp_rtime);
		printf("Transmit timestamp = %d\n",icmp_hdr->icmp_ttime);
		printf("Final timestamp = %.1f\n",final_timestamp);
	    printf("RTT = %.1f ms\n", rtt);
    }
    else return -1;
}//end with line 144