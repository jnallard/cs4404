//Victim software - used for detecting attack flows and complaining to the Victim Gateway
//jnallard, yyan
#include "victim.h"
#include "shared.h"




int main(int argc, char* argv[]){

	char* spoofingIP = NULL;
	if(argc > 1){
		spoofingIP = argv[1];
	}
	char* hostIP = getIPAddress(INTERFACE);


	//Part of this is Recycled/Modified Code from cs4516
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
	

	int bindInt = bind(packet_socket, (struct sockaddr*) &saddr, sizeof(saddr));
	printf("BIND: [%d]\n", bindInt);
	if(bindInt == -1){
		printf("Error [%s]\n", strerror(errno));
		exit(1);
	}

	char buffer[2000];
	AttackList* attackList = NULL;

	//get packet received
	int packetReceived = 0;

	//get current time
	struct timeval startTime;




	while(1){
		int count = recv(packet_socket, buffer, 1500, 0);
		buffer[count] = '\n';
		buffer[count + 1] = '\0';
		char srcIP[33];
		inet_ntop(AF_INET, buffer+12, srcIP, INET_ADDRSTRLEN);
		srcIP[32] = '\0';
		char destIP[33];
		inet_ntop(AF_INET, buffer+16, destIP, INET_ADDRSTRLEN);
		destIP[32] = '\0';

		unsigned char protChar = (unsigned char) buffer[9];
		unsigned int protocol = (unsigned int) protChar;
		//printf("prot [%d]\n", protocol);
		if(protocol == ROUTE_RECORD_PROTOCOL && strcmp(hostIP, destIP) == 0){
			AttackList** entry = (AttackList**) calloc(sizeof(AttackList*), 1);
			attackList = updateAttackCount(attackList, srcIP, entry);
			
			printf("UDP Packet Size: [%d]\n", count);
			printf("UDP Packet Src: [%s]\n", srcIP);
			printf("UDP Packet Dest: [%s]\n", destIP);
			printf("Attack Count: [%d]\n\n", (*entry)->count);

			packetReceived++;
			if(packetReceived == 1){
				gettimeofday(&startTime, NULL);
			}

			//print out packet received and time elapsed for testing
			printf("Number of packets total received: [%d]\n", packetReceived);

			struct timeval currentTime;
			gettimeofday(&currentTime, NULL);
			long currentTimeInMill = currentTime.tv_sec * 1000 + (currentTime.tv_usec) / 1000;
			long startTimeInMill = startTime.tv_sec * 1000 + (startTime.tv_usec) / 1000 ;
			printf("Time elapsed since first packet received: %ld\n", currentTimeInMill - startTimeInMill);


			if((*entry)->count >= ATTACK_COUNT_THRESHOLD){
				printf("Attack Threshold Met for [%s] - Reporting and resetting!\n\n", srcIP);

				//Complain to Victim Gateway Here
				//Create Flow struct based on received Route Record first
				//TODO below: temporary implementation
				RouteRecord* tempRR = readRouteRecord(buffer + 20);

				struct in_addr* victimAddr = getInAddr(destIP);
				if(spoofingIP != NULL){
					victimAddr = getInAddr(spoofingIP);
					printf("Using spoofed Ip Address [%s]\n", spoofingIP);
				}

				struct in_addr* attackerAddr = getInAddr(srcIP);

				Flow* flow = createFlowStruct(victimAddr, attackerAddr, tempRR, createNonce(victimAddr, attackerAddr), 0, AITF_BLOCKING_REQUEST);

				if(flow != NULL){
					sendFlow(VICTIM_GATEWAY_IP, TCP_RECEIVING_PORT, flow);
				}
				else{
					printf("Error reading flow!");
				}
				//Wait T-temp here
				waitMilliseconds(T_TEMP);
				(*entry)->count = 0;
			}
		}
	}
}

//This function increments the attack count for an attacker's source IP address. It will return the start of the list each time, 
//but will store the modified/created entry in the entry pointer, if it is set.
AttackList* updateAttackCount(AttackList* attackList, char* attackerSrcIP, AttackList** entry){
	if(attackList == NULL){
		AttackList* newEntry = (AttackList*) calloc(1, sizeof(AttackList));
		newEntry->srcIP = strdup(attackerSrcIP);
		newEntry->count = 1;
		newEntry->next = NULL;
		if(entry != NULL)
			(*entry) = newEntry;
		return newEntry;
	}

	if(attackList->srcIP != NULL && strcmp(attackList->srcIP, attackerSrcIP) == 0){
		attackList->count = attackList->count + 1;
		if(entry != NULL)
			(*entry) = attackList;
		return attackList;
	}
	else{
		attackList->next = updateAttackCount(attackList->next, attackerSrcIP, entry);
		return attackList;
	}

}
