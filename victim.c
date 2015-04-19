//Victim software - used for detecting attack flows and complaining to the Victim Gateway
//jnallard, yyan

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "victim.h"




int main(int argc, char* argv[]){

	if(argc > 1){
		printf("Arg detected\n");
	}

	int fd;
	struct ifreq ifr;
	char* hostIP;

	//Code learned from http://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	hostIP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

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
				//Wait T-temp here
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
