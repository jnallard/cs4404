//Victim software - used for detecting attack flows and complaining to the Victim Gateway
//jnallard, yyan
#include "shared.h"

#define ATTACK_COUNT_THRESHOLD 20

//This struct is used for determing how many times a source has tried to send messages to the victim
typedef struct AttackList {
	char* srcIP;
	int count;
	struct AttackList* next;
} AttackList;

AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry);

void sendComplaint();


int main(int argc, char* argv[]){

	char* spoofingIP = NULL;
	int guessRandomValue = FALSE;

	//if an argument is provided when running the victim, either the victim will guess
	//the random value, or the spoofed IP address will be used
	if(argc > 1){
		//if argument -rr is provided, victim will guess random value associated with gateways.
		if(strcmp(argv[1], "-rr") == 0){
			guessRandomValue = TRUE;
		}
		//use the spoofed IP instead of the address from the packet
		else{
			spoofingIP = argv[1];
		}
	}
	//Get IP address of this host
	char* hostIP = getIPAddress(INTERFACE);


	//Part of this is Recycled/Modified Code from cs4516
	//create a socket to listen to eth0
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
	AttackList* attackList = NULL;

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

			//Add the entry to the attack list
			AttackList** entry = (AttackList**) calloc(sizeof(AttackList*), 1);
			attackList = updateAttackCount(attackList, srcIP, entry);
			
			printf("UDP Packet Size: [%d]\n", count);
			printf("UDP Packet Src: [%s]\n", srcIP);
			printf("UDP Packet Dest: [%s]\n", destIP);
			printf("Attack Count: [%d]\n\n", (*entry)->count);

			//increment actual count for packets received
			packetsReceived++;

			//If it's the first packet to receive, start timer
			if(packetsReceived == 1){
				gettimeofday(&startTime, NULL);
			}

			//print out packet received and time elapsed for testing
			printf("Number of packets total received: [%d]\n", packetsReceived);

			//Find the elapsed time and print it
			struct timeval currentTime;
			gettimeofday(&currentTime, NULL);
			long currentTimeInMill = currentTime.tv_sec * 1000 + (currentTime.tv_usec) / 1000;
			long startTimeInMill = startTime.tv_sec * 1000 + (startTime.tv_usec) / 1000 ;
			printf("Time elapsed since first packet received: %ld\n", currentTimeInMill - startTimeInMill);


			//Prepare to send complaint message when the attack count threshold is met
			if((*entry)->count >= ATTACK_COUNT_THRESHOLD){
				printf("Attack Threshold Met for [%s] - Reporting and resetting!\n\n", srcIP);

				//Complain to Victim Gateway Here
				//Create Flow struct based on received Route Record first
				RouteRecord* tempRR = readRouteRecord(buffer + 20);

				//If -rr argument is given, guess the random value of the last slot 
				if(guessRandomValue == TRUE){
					tempRR->slot4->randomValue = createLongRandomValue();
				}

				//Get the destination IP from the packet
				struct in_addr* victimAddr = getInAddr(destIP);

				//If the spoofing IP is provided, use it instead of the actual IP
				if(spoofingIP != NULL){
					victimAddr = getInAddr(spoofingIP);
					printf("Using spoofed Ip Address [%s]\n", spoofingIP);
				}

				//Get the attacker IP address
				struct in_addr* attackerAddr = getInAddr(srcIP);

				//Construct the flow struct and send to the victim gateway
				Flow* flow = createFlowStruct(victimAddr, attackerAddr, tempRR, createNonce(victimAddr, attackerAddr), 0, AITF_BLOCKING_REQUEST_VICTIM);

				if(flow != NULL){
					sendFlow(VICTIM_GATEWAY_IP, TCP_RECEIVING_PORT, flow);
				}
				else{
					printf("Error reading flow!");
				}

				//Wait T-temp here
				waitMilliseconds(T_TEMP);

				//Reset count to 0
				(*entry)->count = 0;
			}
		}
	}
}

//This function increments the attack count for an attacker's source IP address. It will return the start of the list each time, 
//but will store the modified/created entry in the entry pointer, if it is set.
AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry){
	//Create the entry if the entry pointer is empty
	if(attackList == NULL){
		AttackList* newEntry = (AttackList*) calloc(1, sizeof(AttackList));
		newEntry->srcIP = strdup(attackerSrcIP);
		newEntry->count = 1;
		newEntry->next = NULL;
		if(entry != NULL)
			(*entry) = newEntry;
		return newEntry;
	}

	//If the list is not empty and the source IP stored in this entry is the same, increment count
	if(attackList->srcIP != NULL && strcmp(attackList->srcIP, attackerSrcIP) == 0){
		attackList->count = attackList->count + 1;
		if(entry != NULL)
			(*entry) = attackList;
		return attackList;
	}
	//Otherwise go to the next entry
	else{
		attackList->next = updateAttackCount(attackList->next, attackerSrcIP, entry);
		return attackList;
	}

}
