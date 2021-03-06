//Victim software - used for detecting attack flows and complaining to the Victim Gateway
//jnallard, yyan
#include "victim.h"
#include "shared.h"




int main(int argc, char* argv[]){

	if(argc > 1){
		printf("Arg detected\n");
	}
	char* hostIP = getIPAddress(INTERFACE);

	printf("Host Interface (%s) Address: [%s]\n", INTERFACE, hostIP);


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

		int protocol = (int) buffer[9];
		if(protocol == 17 && strcmp(hostIP, destIP) == 0){
			AttackList** entry = (AttackList**) calloc(sizeof(AttackList*), 1);
			attackList = updateAttackCount(attackList, srcIP, entry);
			
			printf("UDP Packet Size: [%d]\n", count);
			printf("UDP Packet Src: [%s]\n", srcIP);
			printf("UDP Packet Dest: [%s]\n", destIP);
			printf("Attack Count: [%d]\n\n", (*entry)->count);

			if((*entry)->count > ATTACK_COUNT_THRESHOLD){
				printf("Attack Threshold Met for [%s] - Reporting and resetting!\n\n", srcIP);

				//Complain to Victim Gateway Here
				//Create Flow struct based on received Route Record first
				//TODO below: temporary implementation
				RouteRecord* tempRR = readRouteRecord(buffer + 20);

				struct in_addr* victimAddr = getInAddr(destIP);
				struct in_addr* attackerAddr = getInAddr(srcIP);

				Flow* flow = createFlowStruct(victimAddr, attackerAddr, tempRR, createNonce(victimAddr, attackerAddr), 0, AITF_BLOCKING_REQUEST);

				sendFlow(VICTIM_GATEWAY_IP, TCP_SENDING_PORT, flow);
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
