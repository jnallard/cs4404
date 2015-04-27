
#include "shared.h"

#define IPV4_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8

int inDisobedientMode = FALSE;
int spoofIPAddress = FALSE;

int sockfd;
extern int aitfListeningSocket;

uint16_t ipChecksum(){ //TODO
	return 0;
}

uint16_t udpChecksum(){ //TODO
	return 0;
}


void sigterm(int signum){
	int optval = 1;
	if(setsockopt(aitfListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for listening AITF messages: %s\n", strerror(errno));
	}

	if(close(aitfListeningSocket) != 0){
		printf("close socket for listening AITF messages failed, error: %s\n", strerror(errno));

	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for sending UDP packets: %s\n", strerror(errno));
	}

	if(close(sockfd) != 0){
		printf("close socket for sending UDP packets failed, error: %s\n", strerror(errno));

	}

	printf("Exiting...\n");
	exit(1); 

}


int main(int argc, char** argv){
	struct sigaction action;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);


	if(argc == 1){
		reportError("Usage: sudo attacker true/false [spoof IP address]");
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


	
	char *destIPChar = VICTIM_IP;//TODO: dest ip?? - or use getaddrinfo()? not finished
	char srcIPChar[INET_ADDRSTRLEN];
	//struct addrinfo hints, *res, *p;
	struct sockaddr_in victimAddress;

	printf("Destination IP Address: %s\n", destIPChar);


	//network setup
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sockfd < 0) reportError("socket() failed");

	if(spoofIPAddress == TRUE){
		strcpy(srcIPChar, argv[2]);
	} else {

		// //code learned from http://stackoverflow.com/questions/20800319/how-to-get-my-ip-address-in-c-linux
		// struct ifaddrs *ifaddr, *tmp;
		// if(getifaddrs(&ifaddr) == -1){
		// 	reportError("getifaddrs() failed");
		// }
		// tmp = ifaddr;
		// while(tmp){
		// 	if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
		// 		printf("interface name %s\n", tmp->ifa_name);
		// 		if(strcmp(tmp->ifa_name, INTERFACE) == 0){
		// 			strcpy(srcIPChar, inet_ntoa(((struct sockaddr_in *)tmp->ifa_addr)->sin_addr));
		// 			break;
		// 		}
		// 	}
		// 	tmp = tmp->ifa_next;
		// }
		strcpy(srcIPChar, getIPAddress(INTERFACE));
	}
	//printf("Use IP address %s\n", srcIPChar);

	//get destination information -- TODO
	bzero(&victimAddress, sizeof(victimAddress));
	victimAddress.sin_family = AF_INET;
	victimAddress.sin_port = htons(UDP_PORT);
	if(inet_pton(AF_INET, destIPChar, &(victimAddress.sin_addr)) != 1){
		reportError("inet_pton failed");
	}




	//construct datagram
	//code learned from udp4.c in http://www.pdbuchan.com/rawsock/rawsock.html

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
	udphdr.source = htons(UDP_PORT);
	udphdr.dest = htons(UDP_PORT);
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



	//send packet
	pthread_t listeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);

	AITFMessageListEntry* receivedEntry = NULL;

	while(1){
		//either the attacker is in disobedient mode, or there is no complaint received
		if(inDisobedientMode == TRUE || (receivedEntry = receiveAITFMessage()) == NULL){
			if(sendto(sockfd, packet, IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH, 0, 
						(struct sockaddr*)&victimAddress, sizeof(victimAddress)) < 0){
				printf("Unable to send packet.\n");
			} else {
				printf("Packet sent.\n");
			}
			//wait for T-send before resend the packet
			waitMilliseconds(T_SEND);

		} else if(receivedEntry != NULL && (receivedEntry->flow)->messageType == AITF_BLOCKING_REQUEST) {
			printf("Blocking request received, attacker exits.\n");
			break;

		} else {
			printf("Error receiving AITF message: message type %d\n", (receivedEntry->flow)->messageType);
		}
	}

	killThread(listeningThread);
	
	return 0;
}
