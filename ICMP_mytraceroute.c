#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/sem.h>
#include <poll.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/un.h>
#define SA (struct sockaddr*)
#define HOPLIMIT 30
#define BUFFSIZE 4096

unsigned short csum (unsigned short *, int);
char* get_host_ip(void);

int main (int argc, char *argv[]){
	if (argc != 2) {
		printf ("need for tracert\n");
		exit (0);
	}
	int sd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    //create socket for raw data and icmp protocol

	/* initialize ip header */
	char buf[BUFFSIZE] = { 0 };
	struct ip *ip_hdr = (struct ip *) buf;
	
	int hop = 0; //counter for numer of hops

	//setting socket options
	int one = 1;
	const int *val = &one;
	if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) //checks for header
		printf ("Cannot set HDRINCL!\n");

	/* creates socket */
	struct sockaddr_in addr;
	addr.sin_port = htons (7);
	addr.sin_family = AF_INET;
	inet_pton (AF_INET, argv[1], &(addr.sin_addr));

	printf("Traceroute to ip address %s, %d hops is max\n",argv[1],HOPLIMIT);
	while(hop < HOPLIMIT){
		/* sets ip header values */
		    ip_hdr->ip_hl = 5;
      		ip_hdr->ip_v = 4;
      		ip_hdr->ip_tos = 0;
      		ip_hdr->ip_len = 20 + 8;
      		ip_hdr->ip_id = 10000;
      		ip_hdr->ip_off = 0;
      		ip_hdr->ip_ttl = hop;
      		ip_hdr->ip_p = IPPROTO_ICMP;
      		inet_pton (AF_INET, get_host_ip(), &(ip_hdr->ip_src));
      		inet_pton (AF_INET, argv[1], &(ip_hdr->ip_dst));
      		ip_hdr->ip_sum = csum ((unsigned short *) buf, 9);

		/* creates icmp header and sets values */
      		struct icmphdr *icmphd = (struct icmphdr *) (buf + 20); //adds header after ip header
      		icmphd->type = ICMP_ECHO; // sets type to Echo
      		icmphd->code = 0; // no code
      		icmphd->checksum = 0;
      		icmphd->un.echo.id = 0;
      		icmphd->un.echo.sequence = hop + 1;
      		icmphd->checksum = csum ((unsigned short *) (buf + 20), 4);

		/* Get 3 time values and echo information */
		struct timeval start, end;
		double tms[3];
		int timeout = 0;
		int t = 0;
    	char buff[BUFFSIZE] = {0};
      	struct sockaddr_in addr2;
		for(t = 0; t < 3; t++){
			gettimeofday(&start,NULL);
			/* sends are recieves packet (echos) */
      		sendto (sd, buf, sizeof(struct ip) + sizeof(struct icmphdr), 0, SA & addr, sizeof addr);
			// sets timer for recvfrom
      		struct timeval timer;
			timer.tv_sec = 3;
			setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timer,sizeof(struct timeval));
			socklen_t len = sizeof (struct sockaddr_in);
      		if(recvfrom(sd,buff,sizeof(buff),0,SA&addr2,&len) < 0){
				printf("%2d  * * *\n", hop);
				hop++;
				timeout = -1;
				break;
			}
			gettimeofday(&end,NULL);;
			tms[t] = (end.tv_sec - start.tv_sec) * 1000.0;    //sec to ms
			tms[t] += (end.tv_usec - start.tv_usec) / 1000.0; // us to ms
      	}//end for
		if (timeout < 0) {continue;} // if recvfrom timeout, continue
		
		/* checks if destination was reahed */
		struct icmphdr *icmphd2 = (struct icmphdr *) (buff + 20);
		if(icmphd2->type != 0)
    		printf("%2d  %s  %.3f ms  %.3f ms  %.3f ms\n", hop, inet_ntoa(addr2.sin_addr), tms[0], tms[1], tms[2]);
      	else{
      		printf ("Reached last destination: %s with hop limit: %d\n", inet_ntoa (addr2.sin_addr), hop);
      		exit (0);
    	}

      	hop++; // increments number of hops
    }//end while loop
	return 0;
}//end main

unsigned short csum (unsigned short *buf, int nwords){
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

char* get_host_ip(void){
	struct ifaddrs *ads;
	getifaddrs(&ads);

	while(ads){
		if(ads->ifa_addr && ads->ifa_addr->sa_family == AF_INET){
        	struct sockaddr_in *pAddr = (struct sockaddr_in *)ads->ifa_addr;
        	if (strcmp("eth0",ads->ifa_name) == 0){
				return inet_ntoa(pAddr->sin_addr);
			}
    	}
    	ads = ads->ifa_next;
	}
	return "";
}