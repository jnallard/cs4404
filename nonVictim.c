//Victim software - used for detecting attack flows and complaining to the Victim Gateway
//jnallard, yyan
#include "shared.h"

int main(int argc, char* argv[]){

	//Get the nonvictim's ip address
	char* hostIP = getIPAddress(INTERFACE);
	printf("Host Interface (%s) Address: [%s]\n", INTERFACE, hostIP);


	//Part of this is Recycled/Modified Code from cs4516
	//Create a socket to listen to eth0
	printf("Elevation Handler Started.\n");
	int packet_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	printf("FD: [%d]\n", packet_socket);
	if(packet_socket == -1){
		printf("Error [%s]\n", strerror(errno));
		exit(1);
	}
	struct sockaddr_ll saddr;
	unsigned int interface = if_nametoindex(INTERFACE);
	printf("IF: [%u]\n", interface);
	if(interface == 0){
		printf("Interface not found./n");
		exit(1);
	}

	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = interface;
 	saddr.sll_family = AF_PACKET;
	
 	//Actually bind to eth0 to listen to raw packets
	int bindInt = bind(packet_socket, (struct sockaddr*) &saddr, sizeof(saddr));
	printf("BIND: [%d]\n", bindInt);
	if(bindInt == -1){
		printf("Error [%s]\n", strerror(errno));
		exit(1);
	}

	char buffer[2000];

	//get packet received
	int packetsReceived = 0;
	struct timeval startTime;




	while(1){
		//Received the packet.
		int count = recv(packet_socket, buffer, 1500, 0);
		buffer[count] = '\n';
		buffer[count + 1] = '\0';

		//Get the IP Addresses from the packet
		char srcIP[33];
		inet_ntop(AF_INET, buffer+12, srcIP, INET_ADDRSTRLEN);
		srcIP[32] = '\0';
		char destIP[33];
		inet_ntop(AF_INET, buffer+16, destIP, INET_ADDRSTRLEN);
		destIP[32] = '\0';

		//Get the protocol number
		unsigned char protChar = (unsigned char) buffer[9];
		unsigned int protocol = (unsigned int) protChar;

		//Only care about a flow if has route record info and is actually sent to me
		if(protocol == ROUTE_RECORD_PROTOCOL && strcmp(hostIP, destIP) == 0){
			
			printf("UDP Packet Size: [%d]\n", count);
			printf("UDP Packet Src: [%s]\n", srcIP);
			printf("UDP Packet Dest: [%s]\n", destIP);

			packetsReceived++;

			//If it's the first packet, record the starting time.
			if(packetsReceived == 1){
				gettimeofday(&startTime, NULL);
			}

			//print out packet received and time elapsed for testing
			printf("Number of total packets received: [%d]\n", packetsReceived);

			//Find the elapsed time and print it
			struct timeval currentTime;
			gettimeofday(&currentTime, NULL);
			long currentTimeInMill = currentTime.tv_sec * 1000 + (currentTime.tv_usec) / 1000;
			long startTimeInMill = startTime.tv_sec * 1000 + (startTime.tv_usec) / 1000 ;
			printf("Time elapsed since first packet received: %ld\n", currentTimeInMill - startTimeInMill);
		}
	}
}
