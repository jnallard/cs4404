//attacker.c  This is file is used to represent the attacker in our system, 
//who will send udp packets to the victim and wait for messages from the attacker gateway
//jnallard yyan
#include "shared.h"

//The header length of a default ip packet
#define IPV4_HEADER_LENGTH 20
//The header length of a default udp message
#define UDP_HEADER_LENGTH 8

//This determines is the attacker will stop the flow when requested
int inDisobedientMode = FALSE;
//This determines if the attacker will use a spoofed ip address
int spoofIPAddress = FALSE;

int sockfd;
extern int aitfListeningSocket;
int count;
char *packet;

uint16_t ipChecksum();
uint16_t udpChecksum();
void sigterm(int signum);

//This function will firest determine running options, then start sending flows, while listening for stop messages
int main(int argc, char** argv){

	//Handle the attacker being closed by control commands: ctrl-c, etc.
	struct sigaction action;
	memset(&action, 0, sizeof (struct sigaction));
	action.sa_handler = sigterm;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	//Requires the mode to be set for obedient/disobedient
	if(argc == 1){
		reportError("Usage: sudo attacker true/false [spoof IP address]");
	}

	//determine obedient/disobedient mode
	if(strcmp(argv[1], "false") == 0 || strcmp(argv[1], "FALSE") == 0){
		inDisobedientMode = TRUE;
		printf("Runs in disobedient mode\n");
	}

	//If arg3 is given, use it to spoof an ip address
	if(argc == 3){
		spoofIPAddress = TRUE;
		printf("Spoof IP address enabled\n");
	}

	char *destIPChar = VICTIM_IP;
	char srcIPChar[INET_ADDRSTRLEN];
	//struct addrinfo hints, *res, *p;
	struct sockaddr_in victimAddress;

	//print the destination ip (i.e., the victim)
	printf("Destination IP Address: %s\n", destIPChar);


	//network setup
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sockfd < 0) reportError("socket() failed");

	if(spoofIPAddress == TRUE){
		strcpy(srcIPChar, argv[2]);
	} else {
		strcpy(srcIPChar, getIPAddress(INTERFACE));
	}

	//get destination information
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
	iphdr.ip_sum = ipChecksum();

	//UDP header
	struct udphdr udphdr;
	udphdr.source = htons(UDP_PORT);
	udphdr.dest = htons(UDP_PORT);
	udphdr.len = htons(UDP_HEADER_LENGTH);
	udphdr.check = udpChecksum();//checksum for udp TODO

	//prepare packet 
	packet = (char*)malloc(sizeof(struct ip) + sizeof(struct udphdr));
	memcpy(packet, &iphdr, IPV4_HEADER_LENGTH * sizeof(uint8_t));
	memcpy(packet + IPV4_HEADER_LENGTH, &udphdr, UDP_HEADER_LENGTH * sizeof(uint8_t));
	//no data, thus do not call memcpy for the third time

	//set flag so socket expects us to provide IPv4 header
	int on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		reportError("setsockopt() failed");
	}



	//create a thread to listen for aitf messages
	pthread_t listeningThread = createAITFListeningThread(TCP_RECEIVING_PORT);

	AITFMessageListEntry* receivedEntry = NULL;

	count = 0;
	while(1){
		//either the attacker is in disobedient mode, or there is no complaint received
		if(inDisobedientMode == TRUE || (receivedEntry = receiveAITFMessage()) == NULL){
			//Try to send a packet
			if(sendto(sockfd, packet, IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH, 0, 
						(struct sockaddr*)&victimAddress, sizeof(victimAddress)) < 0){
				printf("Unable to send packet.\n");
			} else {
				count++;

				//In order to not fill up the stdout, we are only printing the first and every ten packets being sent
				if(count == 1){
					printf("First packet sent.\n");
				}
				else if(count % 10 == 0){
					printf("10 packets sent.\n");

				}
			}
			//wait for T-send before resend the packet
			waitMilliseconds(T_SEND);

		} else if(receivedEntry != NULL && (receivedEntry->flow)->messageType == AITF_BLOCKING_REQUEST) {
			//If the attacker is in obeditent mode and receives a message saying to block, exit
			printf("Blocking request received, attacker exits.\n");
			break;

		} else {
			printf("Error receiving AITF message: message type %d\n", (receivedEntry->flow)->messageType);
		}


	}

	//Give some time for the filters to be displayed
	waitMilliseconds(100);

	//Now create a udp message to be sent to the non-victim
	int nonRawSockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in nonVictimAddress;
	char* nonVictimIPChar = NON_VICTIM_IP;
	bzero(&nonVictimAddress, sizeof(nonVictimAddress));
	nonVictimAddress.sin_family = AF_INET;
	nonVictimAddress.sin_port = htons(UDP_PORT);
	if(inet_pton(AF_INET, nonVictimIPChar, &(nonVictimAddress.sin_addr)) != 1){
		reportError("inet_pton failed");
	}

	//Send the packet to the non-victim
	if(sendto(nonRawSockfd, "packet", strlen("packet"), 0, (struct sockaddr*) &nonVictimAddress, sizeof(nonVictimAddress)) < 0){
		printf("error sending packet to non-victim.\n");

	} else {
		printf("Packet sent to non-victim with ip address [%s]\n", nonVictimIPChar);

	}

	//Kill the listening thread
	killThread(listeningThread);

	//print out the total number of packets sent
	printf("Number sent in total [%d]\n", count);
	
	return 0;
}

//This function returns the checksum for the ip packet. We're not actually doing anything, 
//because the gateways do the checksum for us.
uint16_t ipChecksum(){ 
	return 0;
}

//Returns the udp checksum. A zero indicates the checksum is not to be used.
uint16_t udpChecksum(){
	return 0;
}

//The function called when control key to exit is given.
void sigterm(int signum){
	int optval = 1;

	//Wait to make sure everything is setup fine
	waitMilliseconds(100);

	//Send the udp packet to the non-victim
	int nonRawSockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in nonVictimAddress;
	char* nonVictimIPChar = NON_VICTIM_IP;
	bzero(&nonVictimAddress, sizeof(nonVictimAddress));
	nonVictimAddress.sin_family = AF_INET;
	nonVictimAddress.sin_port = htons(UDP_PORT);
	if(inet_pton(AF_INET, nonVictimIPChar, &(nonVictimAddress.sin_addr)) != 1){
		reportError("inet_pton failed");
	}

	if(sendto(nonRawSockfd, "packet", strlen("packet"), 0, (struct sockaddr*) &nonVictimAddress, sizeof(nonVictimAddress)) < 0){
		printf("error sending packet to non-victim.\n");

	} else {
		printf("Packet sent to non-victim with ip address [%s]\n", nonVictimIPChar);

	}



	//sets the sock opts
	if(setsockopt(aitfListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for listening AITF messages: %s\n", strerror(errno));
	}

	//closes the socket used for aitflistening.
	if(close(aitfListeningSocket) != 0){
		printf("close socket for listening AITF messages failed, error: %s\n", strerror(errno));

	}

	//Trying to make the socket reuasable
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval)){
		printf("unable to let other processes to use the same socket for sending UDP packets: %s\n", strerror(errno));
	}

	//Trying to close the udp socket
	if(close(sockfd) != 0){
		printf("close socket for sending UDP packets failed, error: %s\n", strerror(errno));

	}

	printf("Number sent in total [%d]\n", count);

	printf("Exiting...\n");

	exit(1); 

}